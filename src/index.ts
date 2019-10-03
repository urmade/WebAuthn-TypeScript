import path from "path";
import { router as AuthenticationRouter } from "./authentication/router";

import express from "express";3
import dotenv from "dotenv";

const app = express();
dotenv.config();

app.use("/authentication", (req,res,next) => {
	AuthenticationRouter(req,res,next);
})
app.use(express.static("pages"));

app.get("/", (req, res) => {
	res.sendFile(path.join(__dirname, "..", "pages", "signup.html"));
})

app.listen(4430, () => {
	console.log("Server is running on port 4430!");
})