import { GenericAttestation } from "../../custom/GenericAttestation";
import { AuthenticatorData } from "../AuthenticatorData";
import jwt from "jsonwebtoken";
import { Certificate } from "@fidm/x509";
import crypto from "crypto";
import { x5cInterface } from "models/custom/x5cCertificate";

/**
 * Specification: https://w3c.github.io/webauthn/#sctn-android-safetynet-attestation
 */
export interface AndroidSafetyNetAttestation extends GenericAttestation {
	fmt: "android-safetynet";
	attStmt: AndroidSafetyNetStmt;
}

export interface AndroidSafetyNetStmt {
	ver:string;
	response:Buffer;
}

export function isAndroidSafetyNetAttestation(obj: { [key: string]: any }): boolean {
	if (
		obj["fmt"] &&
		obj["fmt"] === "android-safetynet" &&
		obj["attStmt"] &&
		obj["attStmt"]["ver"] &&
		obj["attStmt"]["response"]
	)
		return true;
	return false;
}

export function AndroidSafetyNetVerify(attestation: GenericAttestation, attStmt: AndroidSafetyNetStmt, clientDataHash: Buffer, authenticatorData: AuthenticatorData):boolean {
	const jwsutf = attStmt.response.toString();

	const jws = jwt.decode(jwsutf, {complete: true}) as {[key:string]:any};
	let cert = "-----BEGIN CERTIFICATE-----\n" + jws.header.x5c[0] + "\n-----END CERTIFICATE-----";
	let secCert = "-----BEGIN CERTIFICATE-----\n" + jws.header.x5c[1] + "\n-----END CERTIFICATE-----";

	const decryptCert:x5cInterface = Certificate.fromPEM(Buffer.from(cert)) as any;
	if(!decryptCert.dnsNames.includes("attest.android.com")) return false;

	const verify = crypto.createVerify("RSA-SHA256");
	//if(!verify.verify(secCert,jws.signature)) return false;

	return true;
}