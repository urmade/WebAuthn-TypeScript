import { PublicKeyCredential } from "../models/fido/PublicKeyCredential";
import { User } from "../models/custom/User";
import * as store from "./../storage/persistentKeyStore";
import * as cache from "./../storage/challengeCache";
import { parseAuthenticatorData, sha256 } from "./util";
import crypto from "crypto";
import jwkToPem, { JWK } from "jwk-to-pem";
import { ClientDataJSON } from "models/fido/ClientDataJSON";
import { AuthenticatorData } from "models/fido/AuthenticatorData";

//This method implements the W3C standard for verifying Webauthn login requests. You can find this standard here: https://w3c.github.io/webauthn/#sctn-verifying-assertion
export function verify(assertion:PublicKeyCredential):ErrorMessage {

	//Steps 1 - 3 already fulfilled at the client

	//Step 4: Look up the user in your database
	let user = store.get(assertion.id);
	if(!user) {
		return {
			status: 403,
			text: "This user is not registered at our server!"
		}
	}

	//Steps 5 - 6 already fulfilled at the client

	//Step 7: Convert clientDataJSON (cData) into a JSON object
	//Note: Per specification, the variable name of the parsed JSON has to be C. For readability, C is renamed to clientData in this example
	const clientData:ClientDataJSON = JSON.parse(assertion.response.clientDataJSON);

	//Step 8: Verify that the type of the request is webauthn.get
	if(clientData.type !== "webauthn.get") {
		return {
			status: 403,
			text: "The operation specified in the clientDataJSON is not webauthn.get"
		}
	}

	//Step 9: Verify that the challenge sent by the request matches the original challenge
	if (cache.get(clientData.challenge) === true) {
		return {
			status: 403,
			text: "The challenge of this request has already been resolved, Hint of replay attack"
		}
	}
	//Explicit check, as (cache[clientData.challenge] = undefined) == false => true 
	else if (!cache.get(clientData.challenge) === false) {
		return {
			status: 403,
			text: "The challenge of this request does not match any challenge issued"
		}
	}
	else cache.set(clientData.challenge,true);

	//Step 10: Check that clientData.origin is actually the origin you would expect
	//To specify this, we give our server the URL that it is running on as an environment variable
	//If no environment variable is specified, skip this step
	if (process.env.BASEURL && !(clientData.origin === process.env.BASEURL)) {
		return {
			status: 403,
			text: "The origin of the request does not come from the expected host server"
		}
	}

	//Step 11: Verify that token bindings of clientDataJSON match the tokens of the request. If there is no tokenBinding object in the clientDataJSON, that means that the client doesn't support tokenBindings. The parameter and therefore this step is optional.
	if (clientData.tokenBinding) {
		//TODO Create TLS check
	}

	//Step 12: Verify that authenticatorData.rpIdHash is equal to the SHA256 encoded rpId (Relying Party ID) that we specified in the options at the client
	//If no environment variable is specified, skip this step
	//Note: We first have to decode the authData that we sent as a base64 encoded string to our server
	//Note: For readability, the specified authData variable was renamed into authenticatorData in this implementation
	let authDataBuffer = Buffer.from(assertion.response.authenticatorData, "base64");
	let authenticatorData:AuthenticatorData = parseAuthenticatorData(authDataBuffer);

	if (process.env.RPID && !authenticatorData.rpIdHash.equals(sha256(process.env.RPID))) {
		return {
			status: 403,
			text: "The relying party ID of the request does not match the servers RP ID"
		}
	}

	//Step 13: Verify that AuthenticatorData has the userPresent bit set to 1. The flags attribute in authenticatorData represents a 8bit array (one byte) that encodes possible flags that the client uses to transport information. You can find more detail in the documentation of parseAuthenticatiorData. userPresent is the first bit, meaning that xxxxxxx1 AND 00000001 must be 1.
	if (!(authenticatorData.flags & 1)) {
		return {
			status: 401,
			text: "The request indicates that the user failed the presence test"
		}
	}

	//Step 14:  Verify that AuthenticatorData has the userVerified bit set to 1. This is only necessary when the registration requires prior user authentication (which is the case most times). userVerified is encoded on the third bit, meaning xxxxx1xx AND 00000100 must be at least 4.
	if (!(authenticatorData.flags & 4)) {
		return {
			status: 401,
			text: "The request indicates that the user did not verify before the client sent the request"
		}
	}

	//Step 15: Verify that authenticatorData only contains the extensions that you specified in your options. Extensions are custom JSON key-value pairs that you can use to inject custom data into your authenticatorData object. They are optional and by default your authenticatorData object will not contain an extension attribute
	if (authenticatorData.extensions && process.env.EXPTECTEDEXTENSIONS) {
		let expectedExtensions = process.env.EXPTECTEDEXTENSIONS.split(",");
		let existingExtensions = Object.keys(authenticatorData.extensions);
		for (let i = 0; i < existingExtensions.length; i++) {
			if (!expectedExtensions.includes(existingExtensions[i])) {
				return {
					status: 403,
					text: "The request contains an extension that was not specified in the client-side options"
				}
			}
		}
	}

	//Step 16: Create a hash over clientData using the sha256 algorithm
	let hash = sha256(assertion.response.clientDataJSON);

	//Step 17: Verify that the signature is valid. To do so, concatenate authenticatorData and hash and encrypt it with credentialPublicKey (The key that is stored for our specific user).
	//Note: Verification step copied from https://github.com/MicrosoftEdge/webauthnsample/blob/master/fido.js
	const sig = Buffer.from(assertion.response.signature, 'base64');
	const verify = (user.credentialPublicKey.kty === "RSA") ? crypto.createVerify('RSA-SHA256') : crypto.createVerify('sha256');
	verify.update(authDataBuffer);
	verify.update(hash);
	if (!verify.verify(jwkToPem(user.credentialPublicKey as JWK), sig))
	return {
		status: 403,
		text: "Could not verify the client signature!"
	}

	//Step 18: Verify that the Sign-in count sent in authenticatorData is greater than the signInCount that you have stored in your own database. If this isn't the case, a potential security breach could have happened, but it is up to the server to decide if it wants to invalidate the login
	if(!(authenticatorData.signCount > user.signCount)) {
		return {
			status: 403,
			text: "The Sign-In count of the provided credential doesn't match our records!"
		}
	}
	else user.signCount = authenticatorData.signCount;

	//Step 19: You're done with the verification. Continue the sign-in process however you want.
	return {status: 200, text: "OK"};
}