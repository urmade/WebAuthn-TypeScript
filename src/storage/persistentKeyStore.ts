import { UserCredentials } from "types/fido/UserCredentials";

let store:{[key:string]:UserCredentials} = {};

export function get(key:string) {
	return store[key];
}

export function set(key:string, value:UserCredentials) {
	store[key] = value;
}

export function isDuplicate(key:string):boolean {
	if(store[key]) return true;
	return false;
}