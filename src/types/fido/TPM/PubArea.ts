export interface PubArea {
	authPolicy: Buffer;
	nameAlg: string;
	objectAttributes: {
		adminWithPolicy: boolean;
		decrypt: boolean;
		encryptedDuplication: boolean;
		fixedParent: boolean;
		fixedTPM: boolean;
		noDA: boolean;
		restricted: boolean;
		sensitiveDataOrigin: boolean;
		signORencrypt: boolean;
		stClear: boolean;
		userWithAuth: boolean;
	}
	type: string;
	unique: Buffer;
	parameters: {
		exponent: number;
		keyBits: number;
		scheme: string;
		symmetric: string;
	}
}