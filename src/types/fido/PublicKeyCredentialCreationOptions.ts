export interface PublicKeyCredentialCreationOptions {
	rp: PublicKeyCredentialRpEntity;
	user: PublicKeyCredentialUserEntity;
	challenge: Buffer;
	pubKeyCredParams: Array<PublicKeyCredentialParameters>;
	timeout: number;
	excludeCredentials: Array<PublicKeyCredentialDescriptor>;
	authenticatorSelection: AuthenticatorSelectionCriteria;
	attestation: AttestationConveyancePreference
	extensions: AuthenticationExtensionsClientInputs;
}

interface PublicKeyCredentialRpEntity {

}

interface PublicKeyCredentialUserEntity {

}

interface PublicKeyCredentialParameters {

}

interface PublicKeyCredentialDescriptor {

}

interface AuthenticatorSelectionCriteria {

}

interface AttestationConveyancePreference {

}

interface AuthenticationExtensionsClientInputs {
	
}