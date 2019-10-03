//Global helper variable to dynamically decide which authentication platform to use
var platform = "platform";

//This function starts the registration of a new Credential at the users client. It completes steps 1 + 2 of the specification before sending all data to the server for further processing. The specification can be found here: https://w3c.github.io/webauthn/#sctn-registering-a-new-credential 
async function register(userId, userName, fullName) {
	//To create a new credential that is conform with the WebAuthn standard, we have to provide some options. A complete overview over all options can be found here: https://w3c.github.io/webauthn/#dictionary-makecredentialoptions
	const publicKeyCredentialCreationOptions = {
		//The challenge has to be a random string emitted by our application server, see documentation for getServerSideChallenge
		challenge: Uint8Array.from(
			await getServerSideChallenge(), c => c.charCodeAt(0)).buffer,
		//A string identifier for our server / service. Name is the string displayed to the user when prompted for logging in with our server, id the scope to which our newly scheduled public key will be scoped to.
		rp: {
			name: "Tobis Webserver",
			id: "localhost"
		},
		user: {
			//An user-unique ID in your system. If you use an Identity Provider like Azure Active Directory or Auth0, you can use for example the userId scheduled by these systems as an Id
			id: Uint8Array.from(
				userId, c => c.charCodeAt(0)),
			//User name of the user, e.g. the mail adress with which he normally logs into the page
			name: userName,
			//Real Name of the user
			displayName: fullName
		},
		//Specifies which kinds of algorithms are accepted for the creation of the public key. You can find a full list of algorithm codes here: https://www.iana.org/assignments/cose/cose.xhtml#algorithms 
		//For Windows Hello, you must use { alg: -257, type: "public-key" }
		pubKeyCredParams: [
			{ alg: -7, type: "public-key" },
			{ alg: -257, type: "public-key" }
		],
		//WebAuthn distincts between cross-platform authentication like YubiKeys (e.g. USB sticks that you have to insert into your PC to authenticate) and platform authentication like Windows Hello or Apple Touch ID. 
		//https://w3c.github.io/webauthn/#dictdef-authenticatorselectioncriteria
		authenticatorSelection: {
			//Select authenticators that support username-less flows
			requireResidentKey: true,
			//Select authenticators that have a second factor (e.g. PIN, Bio)
			userVerification: "required",
			authenticatorAttachment: platform
		},
		//Time in Milliseconds the user has to complete the authentication before it times out and failes automatically
		timeout: 60000,
		//Specifies if the relying party (e.g. our server) wishes to know which Authenticator performed the authentication of the user. You can find all details here: https://w3c.github.io/webauthn/#attestation-conveyance
		attestation: "direct"
	};

	//Here a new credential is created which means the client verifies the user (e.g. through Touch ID, Windows Hello,YubiKey, ...) and asks for consent to store a new login credential for this website. If the user agrees, a new credentialObject is scheduled.
	const credential = await navigator.credentials.create({
		publicKey: publicKeyCredentialCreationOptions
	});

	//The credential object is secured by the client and can for example not be sent directly to the server. Therefore we extract all relevant information from the object, transform it to a securely encoded and server-interpretable format and then send it to our server for further verification.
	let attestation = {
		id: base64encode(credential.rawId),
		clientDataJSON: arrayBufferToString(credential.response.clientDataJSON),
		attestationObject: base64encode(credential.response.attestationObject)
	};

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
		if(resp.status == 200) {
			loadLogin();
		}
		else console.error(resp.status + " " + resp.statusText);
	})
}

//This function triggers the verification of an user who already has a credential for this website stored on the client. Steps 1 - 3 as well as 5 - 6 of the specified verification process are already completed at the client, all further validation takes place at the webserver. You can find the full specification here: https://w3c.github.io/webauthn/#sctn-verifying-assertion
async function login(userId) {
	//To create a new credential that is conform with the WebAuthn standard, we have to provide some options. A complete overview over all options can be found here: https://w3c.github.io/webauthn/#dictionary-assertion-options
	const publicKeyCredentialRequestOptions = {
		challenge: Uint8Array.from(
			await getServerSideChallenge(), c => c.charCodeAt(0)
		).buffer,
		timeout: 60000,
		userVerification: "required"
	}

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
		if(resp.status == 200) {
			verifyLogin();
		}
		else console.error(resp.status + " " + resp.statusText);
	})
}

/* --- HELPER FUNCTIONS --- */


/*
When we create a new Public Key for the WebAuthn protocol, we have to provide a challenge which is a random String that our server schedules. This way, when we receive the public key on our server, we can correlate that key with the challenge and mark the challenge as fulfilled. By that, we can mitigate replay attacks as every challenge can only be used once to create a public key. For more details, see https://w3c.github.io/webauthn/#sctn-cryptographic-challenges
*/
async function getServerSideChallenge() {
	let resp = await fetch("/authentication/challenge");
	let string = await resp.text();
	console.log(string);
	return string;
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
	document.cookie = generateId();
	let uname = document.getElementById("uname").value;
	let fname = document.getElementById("fname").value;
	if (uname && fname && document.cookie) {
		BtnLoadUI();
		register(document.cookie, uname, fname);
	}
	else console.error("Parameters missing!");
}
function startLogin() {
	BtnLoadUI();
	login(document.cookie);
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