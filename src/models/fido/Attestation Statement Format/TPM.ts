import { AuthenticatorData } from "../AuthenticatorData";
import { parsePubArea, parseCertInfo, coseToJwk, sha256, ecdaaWarning, algorithmWarning } from "../../../authentication/util";
import { PubArea } from "../TPM/pubArea";
import { CertInfo } from "../TPM/CertInfo";
import jwkToPem, { JWK } from "jwk-to-pem";
import { GenericAttestation } from "../../custom/GenericAttestation";
import * as CBOR from "cbor";
import crypto, { privateDecrypt } from "crypto";
import { Certificate } from "@fidm/x509";
import { x5cInterface } from "models/custom/x5cCertificate";

/**
 * Specification: https://w3c.github.io/webauthn/#sctn-tpm-attestation
 */
export interface TPMAttestation extends GenericAttestation {
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

//To simplify readability and optimize performance, we additionally pass the attestation to have authData as a raw Buffer
export function TPMVerify(attestation: GenericAttestation, attStmt: TPMStmt, clientDataHash: Buffer, authenticatorData: AuthenticatorData): boolean {



	//To work with pubArea and certInfo, we have to convert its Buffer structure into JSONs. Specification and additional information can be found at the respective function documentations.
	let pubArea: PubArea = parsePubArea(attStmt.pubArea) as PubArea;
	let certInfo: CertInfo = parseCertInfo(attStmt.certInfo);

	//Concatenate authData and clientDataHash to attToBeSigned
	const attToBeSigned = Buffer.concat([attestation.authData, clientDataHash]);

	//Check if all information provided in pubInfo is correct
	validatePubInfo(pubArea, authenticatorData);

	//Check if all information provided in certInfo is correct
	validateCertInfo(certInfo, attStmt.pubArea, attToBeSigned);

	if (attStmt.x5c) {
		//Verify the sig is a valid signature over certInfo using the attestation public key in aikCert (x5c first element, caCert second element) with the algorithm specified in alg.
		let x5cString = attStmt.x5c[0].toString("base64");

		//Add headers to cert to make it a valid PEM certificate
		let cert = "-----BEGIN CERTIFICATE-----\n" + x5cString + "\n-----END CERTIFICATE-----";

		//TODO: Abstract algorithm (currently -65535 is hardcoded)
		//A list of all COSE algorithms can be found here (https://www.iana.org/assignments/cose/cose.xhtml#algorithms), a list of all Node.js crypto supported algorithms here (https://stackoverflow.com/questions/14168703/crypto-algorithm-list)
		if (attStmt.alg != -65535) algorithmWarning(attStmt.alg);
		else {
			const verify = crypto.createVerify("RSA-SHA1");
			verify.update(attStmt.certInfo);
			if (!verify.verify(cert, attStmt.sig)) return false;
		}

		//Verify that aikCert meets the requirements in § 8.3.1 TPM Attestation Statement Certificate Requirements.
		//We first have to decode the PEM certificate in order to verify its values
		const decryptCert:any = Certificate.fromPEM(Buffer.from(cert));
		validatex509Cert(decryptCert);
	}
	else if (attStmt.ecdaaKeyId) {
		ecdaaWarning();
		//TODO: Perform ECDAA-Verify on sig to verify that it is a valid signature over certInfo (see [FIDOEcdaaAlgorithm]).
		//Unfortunately no test scenario found so far on which this could have been implemented
	}

	return true;
}

function validatePubInfo(pubArea: PubArea, authenticatorData: AuthenticatorData) {
	//Check if the same algorithms were used to create the Public Key
	if (!pubArea.type.includes(authenticatorData.attestedCredentialData.credentialPublicKey.kty)) return false;

	//Check if the public key encoded in pubAreaKey matches the public key that authenticatorData attested us
	//To check if the public key in authenticatorData matches the public key in pubArea, we have to convert the pubArea unique Buffer into a string
	let pubAreaKey = pubArea.unique.toString("base64");
	if (!(pubAreaKey === authenticatorData.attestedCredentialData.credentialPublicKey.n)) return false;
}

function validateCertInfo(certInfo: CertInfo, pubAreaBuffer: Buffer, attToBeSigned: Buffer) {
	//Check if certInfo.magic is set to "TPM_GENERATED_VALUE". In the specification, this string is encoded by the HEX value 0xFF544347, which translates into the decimal number 4283712327.
	if (!(certInfo.magic === 4283712327)) return false;

	//Check if certInfo.magic is set to "TPM_ST_ATTEST_CERTIF".
	if (!(certInfo.type === "TPM_ST_ATTEST_CERTIFY")) return false;

	//Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
	//TODO abstract alg to work not only with TPM modules (Translate https://www.iana.org/assignments/cose/cose.xhtml#algorithms in https://stackoverflow.com/questions/14168703/crypto-algorithm-list)
	const sha1 = crypto.createHash('sha1');
	sha1.update(attToBeSigned);
	const sha1Secret = sha1.digest();

	if (!sha1Secret.equals(certInfo.extraData)) {
		return false;
	}
	//Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf section 10.12.3
	if (!certInfo.attested.name || !certInfo.attested.qualifiedName) {
		return false;
	}

	//Check if the name of certInfo matches the hash of pubArea with the nameAlg specified in certInfo.attested

	const strippedName = certInfo.attested.name.slice(2);
	//TODO Abstract Hash algorithm
	const pubAreaHash = sha256(pubAreaBuffer);

	if (!strippedName.equals(pubAreaHash)) {
		return false;
	}
}

function validatex509Cert(cert:x5cInterface) {
	//Version MUST be set to 3.
	if (!(cert.version === 3)) return false;
	//Subject field MUST be set to empty.
	if (cert.subject.uniqueId !== null) return false;

	//The Subject Alternative Name extension MUST be set as defined in section 3.2.9 of https://www.trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
	const subAltText = cert.extensions.find((extension) => {
		return extension.name === "subjectAltName";
	})
	const subAltTextBuf = subAltText?subAltText.value:[];
	//TODO parse value, needs to be ASN1 decoded, tcpaTpmManufacturer to be matched with https://trustedcomputinggroup.org/wp-content/uploads/Vendor_ID_Registry_0-8_clean.pdf
	let subAltText64 = subAltTextBuf.toString("base64");

	//The Extended Key Usage extension MUST contain the "joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)" OID
	const extKeyUsage = cert.extensions.find((extension: any) => {
		return extension.name === "extKeyUsage";
	})
	if (extKeyUsage && !(extKeyUsage["2.23.133.8.3"])) return false;

	//The Basic Constraints extension MUST have the CA component set to false.
	const basicConstraints = cert.extensions.find((extension: any) => {
		return extension.name === "basicConstraints";
	})
	if (basicConstraints && basicConstraints.isCA) return false;


	return false;
}