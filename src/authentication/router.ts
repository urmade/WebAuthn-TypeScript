import express from "express";
import bodyParser from "body-parser";
import { issueChallenge } from "./util";
import { registerKey } from "./signup";
import { verify } from "./verify";

export const router = express.Router();

router.use(bodyParser.json());

router.post("/register", (req,res) => {
	let msg = registerKey(req.body.pkc);
	res.status(msg.status).send(msg.text);
})

router.post("/login", (req,res) => {
	let msg = verify(req.body.pkc);
	res.status(msg.status).send(msg.text);
})

router.get("/challenge", (req,res) => {
	issueChallenge(res);
})