export interface CertInfo {
	attested: {
		name: Buffer;
		nameAlg: string;
	};
	clockInfo: {
		clock: Buffer;
		resetCount: number;
		restartCount: number;
		safe: boolean;
	}
	extraData: Buffer;
	firmwareVersion: Buffer;
	magic: number;
	qualifiedSigner: Buffer;
	type: string;
}