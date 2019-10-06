import { parseAuthenticatorData, sha256 } from "./util";
import * as storage from "./../storage/persistentKeyStore";
import * as cache from "./../storage/challengeCache";

import { GenericAttestation } from "../models/custom/GenericAttestation";
import { ClientDataJSON } from "../models/fido/ClientDataJSON";
import { User } from "../models/custom/User";

import { isTPMAttestation, TPMVerify, TPMStmt } from "../models/fido/Attestation Statement Format/TPM"
import { isPackedAttestation, PackedVerify } from "../models/fido/Attestation Statement Format/Packed"
import { isAndroidKeyAttestation, AndroidKeyVerify } from "../models/fido/Attestation Statement Format/Android Key"
import { isAndroidSafetyNetAttestation, AndroidSafetyNetVerify } from "../models/fido/Attestation Statement Format/Android Safety Net"
import { isFIDOU2FAttestation, FIDOU2FVerify } from "../models/fido/Attestation Statement Format/FIDO U2F"
import { isNoneAttestation, NoneVerify } from "../models/fido/Attestation Statement Format/None"

import * as CBOR from "cbor";
import { AuthenticatorData } from "models/fido/AuthenticatorData";

/**
 * 
 * @param keyCredentialObject 
 * @returns Number with HTTP status code to send to an user
 * This method implements the W3C standard that you can find here: https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
 * Note: Variable names are altered from the original protocol for better readability. The original variable names are (custom Name: official Name):
 * clientData: C
 * clientDataHash: hash
 */
export function registerKey(keyCredentialObject: { [key: string]: any }, userId:string): ErrorMessage {
	//Step 1 and 2 of the registering protocol specified by W3C is done at the client
	//Step 3: Parse the clientDataJSON string to a JSON object
	const clientData: ClientDataJSON = JSON.parse(keyCredentialObject.clientDataJSON);

	//Step 4: Verify that clientData.type is webauthn.create
	if (!(clientData.type === "webauthn.create")) {
		return {
			status: 403,
			text: "The operation specified in the clientDataJSON is not webauthn.create"
		}
	}

	//Step 5: Verify that clientData.challenge is the same as the base64 specified challenge in your browsers options.challenge
	//In our cache we store issued challenges and if they were already used (boolean). So if the attribute in our cache doesn't exist or is already true, we have to stop the process.
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

	//Step 6: Check that clientData.origin is actually the origin you would expect
	//To specify this, we give our server the URL that it is running on as an environment variable
	//If no environment variable is specified, skip this step
	if (process.env.BASEURL && !(clientData.origin === process.env.BASEURL)) {
		return {
			status: 403,
			text: "The origin of the request ("+clientData.origin+") does not come from the expected host server"
		}
	}

	//Step 7: Verify that token bindings of clientDataJSON match the tokens of the request. If there is no tokenBinding object in the clientDataJSON, that means that the client doesn't support tokenBindings. The parameter and therefore this step is optional.
	if (clientData.tokenBinding) {
		//TODO Create TLS check
	}

	//Step 8: Hash clientDataJSON with the SHA256 algorithm
	//For understandability, we re-stringify clientData. We could have also used keyCredentialObject.clientDataJSON as this is already the "raw" JSON
	const clientDataHash = sha256(JSON.stringify(clientData));

	//Step 9: Decode the attestationObject using CBOR
	//In this step, we also convert the authData Buffer into an usable JSON
	const attestation: GenericAttestation = CBOR.decodeFirstSync(Buffer.from(keyCredentialObject.attestationObject, 'base64'));
	const authenticatorData: AuthenticatorData = parseAuthenticatorData(attestation.authData);

	//Step 10: Verify that authenticatorData.rpIdHash is equal to the SHA256 encoded rpId (Relying Party ID) that we specified in the options at the client
	//If no environment variable is specified, skip this step
	if (process.env.RPID && !authenticatorData.rpIdHash.equals(sha256(process.env.RPID))) {
		return {
			status: 403,
			text: "The relying party ID of the request does not match the servers RP ID"
		}
	}

	//Step 11: Verify that AuthenticatorData has the userPresent bit set to 1. The flags attribute in authenticatorData represents a 8bit array (one byte) that encodes possible flags that the client uses to transport information. You can find more detail in the documentation of parseAuthenticatiorData. userPresent is the first bit, meaning that xxxxxxx1 AND 00000001 must be 1.
	if (!(authenticatorData.flags & 1)) {
		return {
			status: 403,
			text: "The request indicates that the user failed the presence test"
		}
	}

	//Step 12:  Verify that AuthenticatorData has the userVerified bit set to 1. This is only necessary when the registration requires prior user authentication (which is the case most times). userVerified is encoded on the third bit, meaning xxxxx1xx AND 00000100 must be at least 4.
	if (!(authenticatorData.flags & 4)) {
		return {
			status: 403,
			text: "The request indicates that the user did not verify before the client sent the request"
		}
	}

	//Step 13: Verify that the algorithm used to create the Public key matches one of the allowed encryption methods that you specified in the options on the client side.
	//If no environment variable is specified, skip this step
	if (process.env.ALLOWEDALGORITHMS && !process.env.ALLOWEDALGORITHMS.split(",").includes(authenticatorData.attestedCredentialData.credentialPublicKey.kty)) {
		return {
			status: 403,
			text: "The request used an encryption method that is not allowed by this server"
		}
	}

	//Step 14: Verify that authenticatorData only contains the extensions that you specified in your options. Extensions are custom JSON key-value pairs that you can use to inject custom data into your authenticatorData object. They are optional and by default your authenticatorData object will not contain an extension attribute
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

	//Step 15: Verify that the attestation object in its structure matches one of the specified Attestation Types. These are standardized JSON formats that every provider of WebAutn verifications has to either implement or to register a new standard. All standards are managed by W3C and can currently be found here: https://w3c.github.io/webauthn/#sctn-attstn-fmt-ids

	if (!(
		isTPMAttestation(attestation) ||
		isPackedAttestation(attestation) ||
		isAndroidKeyAttestation(attestation) ||
		isAndroidSafetyNetAttestation(attestation) ||
		isFIDOU2FAttestation(attestation) ||
		isNoneAttestation(attestation)
	)) {
		return {
			status: 403,
			text: "The request doesn't match any known attestation type and can therefore not be processed"
		}
	}

	//Step 16: Verify that the attestation signature is valid. Each Attestation Type has its own verification process, so we have to figure out which attestation type our current request has and handle it accordingly. All verification implementations can be found in the types -> fido -> Attestation Statement Format folde within their respective files. Documentation can be found here: https://w3c.github.io/webauthn/#sctn-attstn-fmt-ids

	let validAttestationSignature = false;

	switch(attestation.fmt) {
		case "tpm":  validAttestationSignature = TPMVerify(attestation, attestation.attStmt as TPMStmt, clientDataHash, authenticatorData); break;
		case "packed":  validAttestationSignature = PackedVerify(attestation,clientDataHash); break;
		case "android-key":  validAttestationSignature = AndroidKeyVerify(attestation,clientDataHash); break;
		case "android-safetynet":  validAttestationSignature = AndroidSafetyNetVerify(attestation,clientDataHash); break;
		case "fido-u2f":  validAttestationSignature = FIDOU2FVerify(attestation,clientDataHash); break;
		case "none":  validAttestationSignature = NoneVerify(); break;
		default: break;
	}
	if(!validAttestationSignature) {
		return {
			status: 403,
			text: "The requests attestation signature could not be verified"
		}
	}

	//Step 17: Obtain a list of acceptable trust anchors (certficates or public keys) for the current attestation type. This Step is positive when you get a trust anchor scheduled using the data given in authData.
	//TODO: Implement Trust anchor acquisition

	//Step 18: Verify the trustworthiness of the attestation. To do so, take the outputs of Step 16 (which by specification would be that the attestation is either self-attested, used ECDAA, used a X.509 certificate or did no attestation at all).
	//Note: For simplicity reasons, we currently only return true or false depending on if all verficiation criteria of the different attestation standards could be met. Therefore we cannot do Step 18.
	//TODO: Implement checks depending on attestation type

	//Step 19: Verify that the credentialId wasn't used by any other user in your storage
	const { StringDecoder } = require('string_decoder');

	const utfDec = new StringDecoder("utf8");
	let utfId = utfDec.write(authenticatorData.attestedCredentialData.credentialId);

	let utfCredentialId = authenticatorData.attestedCredentialData.credentialId.toString('utf8');
	let credentialId = authenticatorData.attestedCredentialData.credentialId.toString('base64');
	if(storage.isDuplicate(credentialId)) {
		return {
			status: 401,
			text: "The credentialId is already in use. Please re-attempt the registration"
		}
	}

	//Step 20: Register the new credentials in your storage
	const credential: User = {
		id: keyCredentialObject.id,
		credentialPublicKey: authenticatorData.attestedCredentialData.credentialPublicKey,
		signCount: authenticatorData.signCount
	};


	storage.set(userId,credential);

	return {status: 200, text:"Registration successful!"};
}