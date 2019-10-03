/**
 * Generic representation of a ClientAttestation. Specific attestation types are specified in types -> fido -> Attestation Statement Format
 */
export interface ClientAttestation {
	authData: Buffer;
	fmt:string;
	attStmt:
	{
		alg: number;
		certInfo: ArrayBuffer;
		sig:ArrayBuffer;
		pubArea: ArrayBuffer;
		ver:string;
		x5c: Array<ArrayBuffer>;
	}
}