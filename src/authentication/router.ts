import express from "express";
import bodyParser from "body-parser";
import { generatePublicKeyCredentialCreationOptions, generatePublicKeyCredentialRequestOptions, testCreateCreds } from "./util";
import { registerKey } from "./signup";
import { verify } from "./verify";

export const router = express.Router();

router.use(bodyParser.json());

router.post("/register", (req,res) => {
	let msg = registerKey(req.body.pkc, req.cookies.userId);
	res.status(msg.status).send(msg.text);
})

router.post("/login", (req,res) => {
	let msg = verify(req.body.pkc, req.cookies.userId);
	res.status(msg.status).send(msg.text);
})

router.get("/creationOptions", (req,res) => {
	res.send(JSON.stringify(generatePublicKeyCredentialCreationOptions()));
})

router.get("/requestOptions", (req,res) => {
	res.send(JSON.stringify(generatePublicKeyCredentialRequestOptions(req.cookies.userId)));
})