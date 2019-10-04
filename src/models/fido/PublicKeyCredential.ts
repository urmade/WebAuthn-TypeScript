export interface PublicKeyCredential {
	id: string;
	rawId: string;
	type?: string;
	response: AuthenticatorResponse;
	discovery?: string;
	identifier?: string;
	clientExtensionResults: {[key:string]:any};

}

interface AuthenticatorResponse {
	authenticatorData: string;
	clientDataJSON: string;
	signature: string;
	userHandle: string;
}