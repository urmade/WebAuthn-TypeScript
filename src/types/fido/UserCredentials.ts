import { JSONWebKey } from "./JSONWebKey";

//TODO Rename, this thing sure has an official name
export interface UserCredentials {
	id: string;
	signCount: number;
	credentialPublicKey: JSONWebKey;
}

