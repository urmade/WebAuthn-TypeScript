//Global helper variable to dynamically decide which authentication platform to use
var platform = "platform";

//This function starts the registration of a new Credential at the users client. It completes steps 1 + 2 of the specification before sending all data to the server for further processing. The specification can be found here: https://w3c.github.io/webauthn/#sctn-registering-a-new-credential 
async function register(userId, userName, fullName) {
	try {
		//To create a new credential that is conform with the WebAuthn standard, we have to provide some options. A complete overview over all options can be found here: https://w3c.github.io/webauthn/#dictionary-makecredentialoptions
		const publicKeyCredentialCreationOptions = await getServerSideCreationOptions();

		publicKeyCredentialCreationOptions.challenge = Uint8Array.from(
			publicKeyCredentialCreationOptions.challenge, c => c.charCodeAt(0)).buffer;
		publicKeyCredentialCreationOptions.user.id = Uint8Array.from(
			userId, c => c.charCodeAt(0));
		publicKeyCredentialCreationOptions.user.name = userName;
		publicKeyCredentialCreationOptions.user.displayName = fullName;
		publicKeyCredentialCreationOptions.authenticatorSelection.authenticatorAttachment = platform;

		//Here a new credential is created which means the client verifies the user (e.g. through Touch ID, Windows Hello,YubiKey, ...) and asks for consent to store a new login credential for this website. If the user agrees, a new credentialObject is scheduled.
		const credential = await navigator.credentials.create({
			publicKey: publicKeyCredentialCreationOptions
		});

		console.log(credential);

		let rawId = new Uint8Array(credential.rawId);

		//The credential object is secured by the client and can for example not be sent directly to the server. Therefore we extract all relevant information from the object, transform it to a securely encoded and server-interpretable format and then send it to our server for further verification.
		let attestation = {
			id: bufferEncode(rawId),
			readableId: credential.id,
			clientDataJSON: arrayBufferToString(credential.response.clientDataJSON),
			attestationObject: base64encode(credential.response.attestationObject)
		};

		console.log(attestation);

		fetch("/authentication/register", {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			redirect: 'follow',
			referrer: 'no-referrer',
			body: JSON.stringify({
				pkc: attestation
			})
		}).then(resp => {
			if (resp.status == 200) {
				loadLogin();
			}
			else {
				resp.text().then((t) => {
					console.error(resp.status + " " + t);
				})
			}
		})
	}
	catch (e) {
		document.getElementById("error").innerHTML = e;
	}

}

//This function triggers the verification of an user who already has a credential for this website stored on the client. Steps 1 - 3 as well as 5 - 6 of the specified verification process are already completed at the client, all further validation takes place at the webserver. You can find the full specification here: https://w3c.github.io/webauthn/#sctn-verifying-assertion
async function login(userId) {
	try {
		//To create a new credential that is conform with the WebAuthn standard, we have to provide some options. A complete overview over all options can be found here: https://w3c.github.io/webauthn/#dictionary-assertion-options
		const publicKeyCredentialRequestOptions = await getServerSideRequestOptions();

		publicKeyCredentialRequestOptions.challenge = Uint8Array.from(
			publicKeyCredentialRequestOptions.challenge, c => c.charCodeAt(0)).buffer;
		publicKeyCredentialRequestOptions.allowCredentials[0].id = bufferDecode(publicKeyCredentialRequestOptions.allowCredentials[0].id);

		console.log(publicKeyCredentialRequestOptions);
		//Here the user is prompted to verify. If the verification succeeds, the client returns an object with all relevant credentials of the user.
		const assertion = await navigator.credentials.get({
			publicKey: publicKeyCredentialRequestOptions
		});

		//The credential object is secured by the client and can for example not be sent directly to the server. Therefore we extract all relevant information from the object, transform it to a securely encoded and server-interpretable format and then send it to our server for further verification.
		const readableAssertion = {
			id: base64encode(assertion.rawId),
			rawId: base64encode(assertion.rawId),
			response: {
				clientDataJSON: arrayBufferToString(assertion.response.clientDataJSON),
				authenticatorData: base64encode(assertion.response.authenticatorData),
				signature: base64encode(assertion.response.signature),
				userHandle: base64encode(assertion.response.userHandle),
			}

		};

		fetch("/authentication/login", {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			redirect: 'follow',
			referrer: 'no-referrer',
			body: JSON.stringify({
				pkc: readableAssertion
			})
		}).then(resp => {
			if (resp.status == 200) {
				verifyLogin();
			}
			else {
				resp.text().then((t) => {
					console.error(resp.status + " " + t);
				})
			}
		})
	}
	catch (e) {
		document.getElementById("error").innerHTML = e;
	}

}

/* --- HELPER FUNCTIONS --- */


/*
When we create a new Public Key for the WebAuthn protocol, we have to provide a challenge which is a random String that our server schedules. This way, when we receive the public key on our server, we can correlate that key with the challenge and mark the challenge as fulfilled. By that, we can mitigate replay attacks as every challenge can only be used once to create a public key. For more details, see https://w3c.github.io/webauthn/#sctn-cryptographic-challenges
*/
async function getServerSideCreationOptions() {
	let resp = await fetch("/authentication/creationOptions");
	let json = await resp.json();
	return json;
}

async function getServerSideRequestOptions() {
	let resp = await fetch("/authentication/requestOptions");
	let json = await resp.json();
	return json;
}

//Function that encodes a UInt8Array to a base64 encoded string
function base64encode(arrayBuffer) {
	if (!arrayBuffer || arrayBuffer.length == 0)
		return undefined;

	return btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)));
}

//Function that converts an ArrayBuffer to a string
function arrayBufferToString(arrayBuffer) {
	return String.fromCharCode.apply(null, new Uint8Array(arrayBuffer));
}

//Gathers all necessary parameters for register() and sets a user cookie to assign him an ID for his "account". This ID is only used at the client-side and is only required to tell the browser with which account the user should be verified (logged in).
function startRegistration() {
	let uid = generateId();
	document.cookie = "userId=" + uid;
	let uname = document.getElementById("uname").value;
	let fname = document.getElementById("fname").value;
	if (uname && fname && uid) {
		BtnLoadUI();
		register(uid, uname, fname);
	}
	else console.error("Parameters missing!");
}
function startLogin() {
	BtnLoadUI();
	let userId = document.cookie.split("=")[1];
	login(userId);
}

function generateId() {
	let charPool = "1234567890qwertzuiopasdfghjklyxcvbnm";
	let rString = "";
	for (let i = 0; i < 32; i++) {
		rString += charPool.charAt(Math.floor(Math.random() * charPool.length));
		if (i % 8 == 0 && i > 0) rString += "-";
	}
	return rString;
}

//Function that correctly encodes the rawId of the credentials object into a string that should match credential.Id
function bufferEncode(value) {
	return base64js.fromByteArray(value)
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=/g, "");
}

//Function to correctly decode credential.Id
function bufferDecode(value) {
	value = value
		.replace(/\-/g, "+")
		.replace(/\_/g, "/");
	return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}