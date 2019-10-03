import { ClientAttestation } from "../ClientAttestation";

/**
 * Specification: https://w3c.github.io/webauthn/#sctn-packed-attestation
 */
export interface PackedAttestation {
	fmt: "packed";
	attStmt: {
		alg: number;
		x5c?:Array<Buffer>;
		ecdaaKeyId?: Buffer;
		sig: Buffer;
	}
}

export function isPackedAttestation(obj:{[key:string]:any}):boolean {
	if(
		obj["fmt"] &&
		obj["fmt"] === "packed" &&
		obj["attStmt"] &&
		obj["attStmt"]["alg"] &&
		(
			obj["attStmt"]["x5c"] ||
			obj["attStmt"]["ecdaaKeyId"]
		) &&
		obj["attStmt"]["sig"]
	)
	return true;
	return false;
}

export function PackedVerify(attestation:ClientAttestation, clientDataHash:Buffer):boolean {
	//TODO
	return true;
}