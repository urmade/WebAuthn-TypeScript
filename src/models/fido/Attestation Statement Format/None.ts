import { GenericAttestation } from "models/custom/GenericAttestation";

/**
 * Specification: https://w3c.github.io/webauthn/#sctn-none-attestation
 */
export interface NoneAttestation extends GenericAttestation {
	fmt: "none";
	attStmt: {}
}
export function isNoneAttestation(obj: { [key: string]: any }): boolean {
	if (
		obj["fmt"] &&
		obj["fmt"] === "none" &&
		obj["attStmt"]
	)
		return true;
	return false;
}

export function NoneVerify():boolean {
	//TODO
	return true;
}