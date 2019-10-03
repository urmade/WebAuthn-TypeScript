/**
 * Generic representation of a ClientAttestation. Specific attestation types are specified in types -> fido -> Attestation Statement Format
 * https://w3c.github.io/webauthn/#attestation-statement
 */
export interface GenericAttestation {
	authData: Buffer;
	fmt: string;
	attStmt:
	{
		// alg: number;
		// certInfo: ArrayBuffer;
		// sig: ArrayBuffer;
		// pubArea: ArrayBuffer;
		// ver: string;
		// x5c: Array<ArrayBuffer>;
	}
}