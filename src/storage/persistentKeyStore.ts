import { User } from "types/custom/User";

let store:{[key:string]:User} = {};

export function get(key:string) {
	return store[key];
}

export function set(key:string, value:User) {
	store[key] = value;
}

export function isDuplicate(key:string):boolean {
	if(store[key]) return true;
	return false;
}