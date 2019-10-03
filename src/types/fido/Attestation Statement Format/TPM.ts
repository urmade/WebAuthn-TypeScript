import { AuthenticatorData } from "../AuthenticatorData";
import { parsePubArea, parseCertInfo, coseToJwk, sha256 } from "./../../../authentication/util";
import { PubArea } from "../TPM/pubArea";
import { CertInfo } from "../TPM/CertInfo";
import { ClientAttestation } from "../ClientAttestation";
import * as CBOR from "cbor";
import crypto from "crypto";

/**
 * Specification: https://w3c.github.io/webauthn/#sctn-tpm-attestation
 */
export interface TPMAttestation {
	fmt: "tpm";
	attStmt: TPMStmt;
}

export interface TPMStmt {
	ver: "2.0";
	alg: number;
	x5c?: Array<Buffer>;
	ecdaaKeyId?: Buffer;
	sig: Buffer;
	certInfo: Buffer;
	pubArea: Buffer;
}

export function isTPMAttestation(obj: { [key: string]: any }): boolean {
	if (
		obj["fmt"] &&
		obj["fmt"] === "tpm" &&
		obj["attStmt"] &&
		obj["attStmt"]["ver"] &&
		obj["attStmt"]["ver"] === "2.0" &&
		obj["attStmt"]["alg"] &&
		(
			obj["attStmt"]["x5c"] ||
			obj["attStmt"]["ecdaaKeyId"]
		) &&
		obj["attStmt"]["sig"] &&
		obj["attStmt"]["certInfo"] &&
		obj["attStmt"]["pubArea"]
	)
		return true;
	return false;
}

//To simplify the function flow, we pass the whole attestation with its raw buffer and attStmt in its parsed form.
export function TPMVerify(attestation:ClientAttestation,attStmt: TPMStmt, clientDataHash: Buffer, authenticatorData: AuthenticatorData): boolean {
	//To work with pubArea and certInfo, we have to convert its Buffer structure into JSONs. Specification and additional information can be found at the respective function documentations.
	let pubArea:PubArea = parsePubArea(attStmt.pubArea) as PubArea;
	let certInfo:CertInfo = parseCertInfo(attStmt.certInfo);
	
	//Check if the same algorithms were used to create the Public Key
	if(!pubArea.type.includes(authenticatorData.attestedCredentialData.credentialPublicKey.kty)) return false;

	//Check if the public key encoded in pubAreaKey matches the public key that authenticatorData attested us
	//To check if the public key in autenticatorData matches the public key in pubArea, we have to convert the pubArea unique Buffer into a string
	let pubAreaKey = pubArea.unique.toString("base64");
	if(!(pubAreaKey === authenticatorData.attestedCredentialData.credentialPublicKey.n)) return false;

	//Check if certInfo.magic is set to "TPM_GENERATED_VALUE". In the specification, this string is encoded by the HEX value 0xFF544347, which translates into the decimal number 4283712327.
	if(!(certInfo.magic === 4283712327)) return false;

	//Check if certInfo.magic is set to "TPM_ST_ATTEST_CERTIF".
	if(!(certInfo.type === "TPM_ST_ATTEST_CERTIFY")) return false;

	//TODO: Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".

	//TODO: Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in [TPMv2-Part2] section 10.12.3, whose name field contains a valid Name for pubArea, as computed using the algorithm in the nameAlg field of pubArea using the procedure specified in [TPMv2-Part1] section 16.

	if(attStmt.x5c) {
		//TODO: Verify the sig is a valid signature over certInfo using the attestation public key in aikCert with the algorithm specified in alg.

		//TODO: Verify that aikCert meets the requirements in § 8.3.1 TPM Attestation Statement Certificate Requirements.

		//TODO: If aikCert contains an extension with OID 1 3 6 1 4 1 45724 1 1 4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData.
	}
	else if (attStmt.ecdaaKeyId) {
		//TODO: Perform ECDAA-Verify on sig to verify that it is a valid signature over certInfo (see [FIDOEcdaaAlgorithm]).
	}

	return true;
}