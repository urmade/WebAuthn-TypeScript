/**
 * https://w3c.github.io/webauthn/#client-data
 */
export interface ClientDataJSON {
	challenge:string;
	origin:string;
	type:"webauthn.create" | "webauthn.get";
	tokenBinding?: {
		status: "supported" | "present";
		id:string;
	}
}