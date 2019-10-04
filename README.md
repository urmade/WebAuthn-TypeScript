# WebAuthn Typescript implementation
WebAuthn is an exciting technology that brings native login capabilites like Windows Hello, Apple Touch ID or YubiKeys into the web. This enables developers to build sign-in experiences where users don't create passwords and store all their security-related data directly on their device, protected by built-in hardware.

To create awareness for this awesome technology and give developers a headstart on how to start implementing WebAuthn, this project was created. Please read the notes in this readme to get started and make sure to check out [this hosted demo]() of the project.

## Special Thanks to:
[Yuriy Ackermann](https://github.com/herrjemand), his [Medium article](https://medium.com/@herrjemand/verifying-fido-tpm2-0-attestation-fc7243847498) and his [demo implementation](https://github.com/fido-alliance/webauthn-demo/tree/completed-demo). The resources provided by him offer great information around the standard and include awesome implementations for complex tasks like Buffer decoding.

Microsoft and their [WebAuthn Sample](https://github.com/MicrosoftEdge/webauthnsample). They have a great documentation on WebAuthn and have a very clean and intuitive implementation of many cryptography challenges in the standard.

Duo Security and their [WebAuthn Guide](https://webauthn.guide/). Possibly the greatest learning website I've ever seen and an extremely well documented theoretical introduction that connects seamlessly the ideas of WebAuthn and the concrete specification provided by W3C.

## What should I use this project for?
For one, it is a (nearly) complete implementation of the W3C specification draft for Web Authentication. As that, it can be used as an inspiration for a productive implementation of this protocol (as already indicated, not all verification steps are yet implemented, so please don't use this as-is for any production systems. If you however implement the missing steps, feel free to create a Pull request ;-) ). 

And second this project should help interested developers to better understand what WebAuthn is all about. The code is extensively documented and contains a lot of references to the original standard so you always know which line of code implements which paragraph. Feel free to use this project for learning and teaching projects as much as you want.

## Where can I get more theory about WebAuthn?
As mentioned in the special thanks section, the Duo Security [WebAuthn Guide](https://webauthn.guide/) is a great starting point to understand the idea behind WebAuthn. Microsoft also offers an [extensive introduction](https://docs.microsoft.com/en-us/microsoft-edge/dev-guide/windows-integration/web-authentication) to this topic. If you want to go deeper, I can recommend Yuriy Ackermanns [blog articles](https://medium.com/@herrjemand) as they cover a lot of implementation-level concepts and offer context to some standards used in the WebAuthn specification. And of course you should read the [WebAuthn specification](https://w3c.github.io/webauthn/)!

## How do I get started?
You will need Node.js and TypeScript to run it. Node.js can be downloaded [here](https://nodejs.org/en/download/).To install TypeScript, go to your console and run `npm install -g typescript`. 

When you've installed the basic setup, clone this repository and run `npm install`, `tsc` and `node dest/index` in this order. Your server is now accessible at `localhost:4430` and you can start playing around.

The WebAuthn specification has two interesting parts for Web Developers: Registering a new user in your app and verifying logins of said user. In the code sample, you can find the server-side implementation of these steps in src -> authentication -> signup.ts / verify.ts. All client-side (web browser) related implementation can be found in pages -> webauthn.js. Click through these files and read the comments to learn about the general implementation flow. If you want to dig deeper, many of the comments already have references to the part of the specification that they are implementing. Read through this and understand how the specification was brought into this server (or find errors and let me know ;-) ).