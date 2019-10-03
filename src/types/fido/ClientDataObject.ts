export interface ClientDataObject {
	challenge:string;
	origin:string;
	//TODO: Type should be enum
	type:string;
	tokenBinding?: {
		status:string
	}
}