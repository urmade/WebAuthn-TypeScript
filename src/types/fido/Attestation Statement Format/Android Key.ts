import { ClientAttestation } from "../ClientAttestation";

/**
 * Specification: https://w3c.github.io/webauthn/#sctn-android-key-attestation
 */
export interface AndroidKeyAttestation {
	fmt: "android-key";
	attStmt: {
		alg: number;
		x5c: Array<Buffer>;
		sig: Buffer;
	}
}

export function isAndroidKeyAttestation(obj: { [key: string]: any }): boolean {
	if (
		obj["fmt"] &&
		obj["fmt"] === "android-key" &&
		obj["attStmt"] &&
		obj["attStmt"]["alg"] &&
		obj["attStmt"]["x5c"] &&
		obj["attStmt"]["sig"]
	)
		return true;
	return false;
}

export function AndroidKeyVerify(attestation:ClientAttestation, clientDataHash:Buffer):boolean {
	//TODO
	return true;
}