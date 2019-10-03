import { ClientAttestation } from "../ClientAttestation";

/**
 * Specification: https://w3c.github.io/webauthn/#sctn-android-safetynet-attestation
 */
export interface AndroidSafetyNetAttestation {
	fmt: "android-safetynet";
	attStmt: {
		ver: string;
		response: Buffer;
	}
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

export function AndroidSafetyNetVerify(attestation:ClientAttestation, clientDataHash:Buffer):boolean {
	//TODO
	return true;
}