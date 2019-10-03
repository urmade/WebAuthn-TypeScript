export interface ClientAssertion {
	id: string;
	rawId: string;
	type: string;
	response: {
		authenticatorData: string;
		clientDataJSON: string;
		signature: string;
		userHandle: string;
	}

}