import { JSONWebKey } from "../custom/JSONWebKey";

/**
 * Specification: https://w3c.github.io/webauthn/#sctn-attested-credential-data
 */
export interface AttestedCredentialData {
	aaguid: string;
	credentialId: Buffer;
	credentialIdLength: number;
	credentialPublicKey: JSONWebKey;
}