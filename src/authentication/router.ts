import express from "express";
import bodyParser from "body-parser";
import { issueChallenge } from "./util";
import { registerKey } from "./signup";
import { verify } from "./verify";

export const router = express.Router();

router.use(bodyParser.json());

router.post("/register", (req,res) => {
	registerKey(req.body.pkc);
	res.send("Successful!");
})

router.post("/login", (req,res) => {
	verify(req.body.pkc);
	res.send("Successful login!");
})

router.get("/challenge", (req,res) => {
	issueChallenge(res);
})