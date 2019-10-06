import path from "path";
import { router as AuthenticationRouter } from "./authentication/router";

import express from "express";3
import dotenv from "dotenv";
import cookies from "cookie-parser";

const app = express();
dotenv.config();

app.use(cookies());

app.use("/authentication", (req,res,next) => {
	AuthenticationRouter(req,res,next);
})
app.use(express.static("pages"));

app.get("/", (req, res) => {
	res.sendFile(path.join(__dirname, "..", "pages", "signup.html"));
})

app.listen(process.env.PORT || 4430, () => {
	console.log("Server is running on port 4430!");
})