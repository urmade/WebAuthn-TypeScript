import crypto from "crypto";

import * as cache from "./../storage/challengeCache";

import * as uuid from "uuid-parse";
import * as CBOR from "cbor";
import { Response } from "express";
import { AuthenticatorData } from "types/fido/AuthenticatorData";

//Function logic copied from Microsoft demo implementation: https://github.com/MicrosoftEdge/webauthnsample/blob/master/fido.js
//Decrypt the authData Buffer and split it in its single information pieces. Its structure is specified here: https://w3c.github.io/webauthn/#authenticator-data
export function parseAuthenticatorData(authData: Buffer) {
	try {
		const authenticatorData: any = {};


		authenticatorData.rpIdHash = authData.slice(0, 32);
		authenticatorData.flags = authData[32];
		authenticatorData.signCount = (authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | (authData[36]);

		//Check if the client sent attestedCredentialdata, which is necessary for every new public key scheduled. This is indicated by the 6th bit of the flag byte being 1 (See specification at function start for reference)
		if (authenticatorData.flags & 64) {
			//Extract the data from the Buffer. Reference of the structure can be found here: https://w3c.github.io/webauthn/#sctn-attested-credential-data
			const attestedCredentialData: { [key: string]: any } = {};
			attestedCredentialData.aaguid = uuid.unparse(authData.slice(37, 53)).toUpperCase();
			attestedCredentialData.credentialIdLength = (authData[53] << 8) | authData[54];
			attestedCredentialData.credentialId = authData.slice(55, 55 + attestedCredentialData.credentialIdLength);
			//Public key is the first CBOR element of the remaining buffer
			const publicKeyCoseBuffer = authData.slice(55 + attestedCredentialData.credentialIdLength, authData.length);

			//convert public key to JWK for storage
			attestedCredentialData.credentialPublicKey = coseToJwk(publicKeyCoseBuffer);

			authenticatorData.attestedCredentialData = attestedCredentialData;
		}

		//Check for extension data in the authData, which is indicated by the 7th bit of the flag byte being 1 (See specification at function start for reference)
		if (authenticatorData.flags & 128) {
			//has extension data

			let extensionDataCbor;

			if (authenticatorData.attestedCredentialData) {
				//if we have attesttestedCredentialData, then extension data is
				//the second element
				extensionDataCbor = CBOR.decodeAllSync(authData.slice(55 + authenticatorData.attestedCredentialData.credentialIdLength, authData.length));
				extensionDataCbor = extensionDataCbor[1];
			} else {
				//Else it's the first element
				extensionDataCbor = CBOR.decodeFirstSync(authData.slice(37, authData.length));
			}

			authenticatorData.extensionData = CBOR.encode(extensionDataCbor).toString('base64');
		}

		return authenticatorData;
	} catch (e) {
		throw new Error("Authenticator Data could not be parsed")
	}
}
//Convert the Public Key from the cose format to jwk format
export function coseToJwk(cose: any) {
	try {
		let publicKeyJwk = {};
		const publicKeyCbor = CBOR.decodeFirstSync(cose);
		//Determine which encryption method was used to create the public key
		if (publicKeyCbor.get(3) == -7) {
			publicKeyJwk = {
				kty: "EC",
				crv: "P-256",
				x: publicKeyCbor.get(-2).toString('base64'),
				y: publicKeyCbor.get(-3).toString('base64')
			}
		} else if (publicKeyCbor.get(3) == -257) {
			publicKeyJwk = {
				kty: "RSA",
				n: publicKeyCbor.get(-1).toString('base64'),
				e: publicKeyCbor.get(-2).toString('base64')
			}
		} else {
			throw new Error("Unknown public key algorithm");
		}

		return publicKeyJwk;
	} catch (e) {
		throw new Error("Could not decode COSE Key");
	}
}

//Hash a given data with the SHA256 algorithm
export function sha256(data: any) {
	const hash = crypto.createHash('sha256');
	hash.update(data);
	return hash.digest();
}

function generateChallenge() {
	let charPool = "1234567890qwertzuiopasdfghjklyxcvbnm";
	let rString = "";
	for (let i = 0; i < 32; i++) {
		rString += charPool.charAt(Math.floor(Math.random() * charPool.length));
	}
	return rString;
}

//As Webauthn provides us only with the challenge as a base64 encoded string, we have to manually convert the scheduled plaintext string
function base64encode(string: string) {
	let buff = Buffer.from(string);
	let base64String = buff.toString('base64');
	return base64String.substring(0, base64String.length - 1);
}

export function issueChallenge(res: Response) {
	let rString = generateChallenge();

	//Store the issued challenge in a cache to verify incoming requests later
	//Before caching, convert the string to Base64 as that is how the string will be represented in all client-scheduled objects
	cache.set(base64encode(rString),false);
	res.send(rString);
}

//Copied from https://medium.com/@herrjemand/verifying-fido-tpm2-0-attestation-fc7243847498
//Full specification can be found here (Chapter 10.12.8): https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
export function parseCertInfo(certInfoBuffer:Buffer) {
    let magicBuffer = certInfoBuffer.slice(0, 4);
    let magic = magicBuffer.readUInt32BE(0);
    certInfoBuffer = certInfoBuffer.slice(4);

	let typeBuffer = certInfoBuffer.slice(0, 2);
	//@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
    let type = TPM_ST[typeBuffer.readUInt16BE(0)];
    certInfoBuffer = certInfoBuffer.slice(2);

    let qualifiedSignerLength = certInfoBuffer.slice(0, 2).readUInt16BE(0);
    certInfoBuffer  = certInfoBuffer.slice(2);
    let qualifiedSigner = certInfoBuffer.slice(0, qualifiedSignerLength);
    certInfoBuffer  = certInfoBuffer.slice(qualifiedSignerLength);

    let extraDataLength = certInfoBuffer.slice(0, 2).readUInt16BE(0);
    certInfoBuffer  = certInfoBuffer.slice(2);
    let extraData   = certInfoBuffer.slice(0, extraDataLength);
    certInfoBuffer  = certInfoBuffer.slice(extraDataLength);

    let clockInfo = {
        clock: certInfoBuffer.slice(0, 8),
        resetCount: certInfoBuffer.slice(8, 12).readUInt32BE(0),
        restartCount: certInfoBuffer.slice(12, 16).readUInt32BE(0),
        safe: !!(certInfoBuffer[16])
    }
    certInfoBuffer  = certInfoBuffer.slice(17);

    let firmwareVersion = certInfoBuffer.slice(0, 8);
    certInfoBuffer      = certInfoBuffer.slice(8);

    let attestedNameBufferLength = certInfoBuffer.slice(0, 2).readUInt16BE(0)
    let attestedNameBuffer = certInfoBuffer.slice(2, attestedNameBufferLength + 2);
    certInfoBuffer = certInfoBuffer.slice(2 + attestedNameBufferLength)

    let attestedQualifiedNameBufferLength = certInfoBuffer.slice(0, 2).readUInt16BE(0)
    let attestedQualifiedNameBuffer = certInfoBuffer.slice(2, attestedQualifiedNameBufferLength + 2);
    certInfoBuffer = certInfoBuffer.slice(2 + attestedQualifiedNameBufferLength)

    let attested = {
		//@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
        nameAlg: TPM_ALG[attestedNameBuffer.slice(0, 2).readUInt16BE(0)],
        name: attestedNameBuffer,
        qualifiedName: attestedQualifiedNameBuffer
    }

    return {
        magic,
        type,
        qualifiedSigner,
        extraData,
        clockInfo,
        firmwareVersion,
        attested
    }
}

//Copied from https://medium.com/@herrjemand/verifying-fido-tpm2-0-attestation-fc7243847498
//Full specification can be found here (Chapter 12.2.4): https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
export function parsePubArea (pubAreaBuffer:Buffer) {
	let typeBuffer = pubAreaBuffer.slice(0, 2);
	//@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
    let type = TPM_ALG[typeBuffer.readUInt16BE(0)];
    pubAreaBuffer = pubAreaBuffer.slice(2);

	let nameAlgBuffer = pubAreaBuffer.slice(0, 2)
	//@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
    let nameAlg = TPM_ALG[nameAlgBuffer.readUInt16BE(0)];
    pubAreaBuffer = pubAreaBuffer.slice(2);

    let objectAttributesBuffer = pubAreaBuffer.slice(0,4);
    let objectAttributesInt    = objectAttributesBuffer.readUInt32BE(0);
    let objectAttributes = {
        fixedTPM:             !!(objectAttributesInt & 1),
        stClear:              !!(objectAttributesInt & 2),
        fixedParent:          !!(objectAttributesInt & 8),
        sensitiveDataOrigin:  !!(objectAttributesInt & 16),
        userWithAuth:         !!(objectAttributesInt & 32),
        adminWithPolicy:      !!(objectAttributesInt & 64),
        noDA:                 !!(objectAttributesInt & 512),
        encryptedDuplication: !!(objectAttributesInt & 1024),
        restricted:           !!(objectAttributesInt & 32768),
        decrypt:              !!(objectAttributesInt & 65536),
        signORencrypt:        !!(objectAttributesInt & 131072)
    }
    pubAreaBuffer = pubAreaBuffer.slice(4);

    let authPolicyLength = pubAreaBuffer.slice(0, 2).readUInt16BE(0);
    pubAreaBuffer  = pubAreaBuffer.slice(2);
    let authPolicy = pubAreaBuffer.slice(0, authPolicyLength);
    pubAreaBuffer  = pubAreaBuffer.slice(authPolicyLength);

    let parameters = undefined;
    if(type === 'TPM_ALG_RSA') {
        parameters = {
			//@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
			symmetric: TPM_ALG[pubAreaBuffer.slice(0, 2).readUInt16BE(0)],
			//@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
            scheme:    TPM_ALG[pubAreaBuffer.slice(2, 4).readUInt16BE(0)],
            keyBits:   pubAreaBuffer.slice(4, 6).readUInt16BE(0),
            exponent:  pubAreaBuffer.slice(6, 10).readUInt32BE(0)
        }
        pubAreaBuffer  = pubAreaBuffer.slice(10);
    } else if(type === 'TPM_ALG_ECC') {
        parameters = {
			//@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
			symmetric: TPM_ALG[pubAreaBuffer.slice(0, 2).readUInt16BE(0)],
			//@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
			scheme:    TPM_ALG[pubAreaBuffer.slice(2, 4).readUInt16BE(0)],
			//@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
			curveID:   TPM_ECC_CURVE[pubAreaBuffer.slice(4, 6).readUInt16BE(0)],
			//@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
            kdf:       TPM_ALG[pubAreaBuffer.slice(6, 8).readUInt16BE(0)]
        }
        pubAreaBuffer  = pubAreaBuffer.slice(8);
    } else 
        throw new Error(type + ' is an unsupported type!');

    let uniqueLength = pubAreaBuffer.slice(0, 2).readUInt16BE(0);
    pubAreaBuffer  = pubAreaBuffer.slice(2);
    let unique = pubAreaBuffer.slice(0, uniqueLength);
    pubAreaBuffer  = pubAreaBuffer.slice(uniqueLength);

    return {
        type,
        nameAlg,
        objectAttributes,
        authPolicy,
        parameters,
        unique
    }
}


function getEndian() {
    let arrayBuffer = new ArrayBuffer(2);
    let uint8Array = new Uint8Array(arrayBuffer);
    let uint16array = new Uint16Array(arrayBuffer);
    uint8Array[0] = 0xAA; // set first byte
    uint8Array[1] = 0xBB; // set second byte

    if(uint16array[0] === 0xBBAA)
        return 'little';
    else
        return 'big';
}

function readBE16(buffer:Buffer) {
    if(buffer.length !== 2)
        throw new Error('Only 2byte buffer allowed!');

    if(getEndian() !== 'big')
        buffer = buffer.reverse();

    return new Uint16Array(buffer.buffer)[0]
}

function readBE32 (buffer:Buffer) {
    if(buffer.length !== 4)
        throw new Error('Only 4byte buffers allowed!');

    if(getEndian() !== 'big')
        buffer = buffer.reverse();

    return new Uint32Array(buffer.buffer)[0]
}


let TPM_ALG = {
    0x0000: "TPM_ALG_ERROR",
    0x0001: "TPM_ALG_RSA",
    0x0003: "TPM_ALG_SHA",
    0x0004: "TPM_ALG_SHA1",
    0x0005: "TPM_ALG_HMAC",
    0x0006: "TPM_ALG_AES",
    0x0007: "TPM_ALG_MGF1",
    0x0008: "TPM_ALG_KEYEDHASH",
    0x000A: "TPM_ALG_XOR",
    0x000B: "TPM_ALG_SHA256",
    0x000C: "TPM_ALG_SHA384",
    0x000D: "TPM_ALG_SHA512",
    0x0010: "TPM_ALG_NULL",
    0x0012: "TPM_ALG_SM3_256",
    0x0013: "TPM_ALG_SM4",
    0x0014: "TPM_ALG_RSASSA",
    0x0015: "TPM_ALG_RSAES",
    0x0016: "TPM_ALG_RSAPSS",
    0x0017: "TPM_ALG_OAEP",
    0x0018: "TPM_ALG_ECDSA",
    0x0019: "TPM_ALG_ECDH",
    0x001A: "TPM_ALG_ECDAA",
    0x001B: "TPM_ALG_SM2",
    0x001C: "TPM_ALG_ECSCHNORR",
    0x001D: "TPM_ALG_ECMQV",
    0x0020: "TPM_ALG_KDF1_SP800_56A",
    0x0021: "TPM_ALG_KDF2",
    0x0022: "TPM_ALG_KDF1_SP800_108",
    0x0023: "TPM_ALG_ECC",
    0x0025: "TPM_ALG_SYMCIPHER",
    0x0026: "TPM_ALG_CAMELLIA",
    0x0040: "TPM_ALG_CTR",
    0x0041: "TPM_ALG_OFB",
    0x0042: "TPM_ALG_CBC",
    0x0043: "TPM_ALG_CFB",
    0x0044: "TPM_ALG_ECB"
}

let TPM_ECC_CURVE = {
    0x0000: "TPM_ECC_NONE",
    0x0001: "TPM_ECC_NIST_P192",
    0x0002: "TPM_ECC_NIST_P224",
    0x0003: "TPM_ECC_NIST_P256",
    0x0004: "TPM_ECC_NIST_P384",
    0x0005: "TPM_ECC_NIST_P521",
    0x0010: "TPM_ECC_BN_P256",
    0x0011: "TPM_ECC_BN_P638",
    0x0020: "TPM_ECC_SM2_P256"
}

let TPM_CC = {
    0x0000010F: "TPM_CC_FIRST",
    0x0000011F: "TPM_CC_NV_UndefineSpaceSpecial",
    0x00000120: "TPM_CC_EvictControl",
    0x00000121: "TPM_CC_HierarchyControl",
    0x00000122: "TPM_CC_NV_UndefineSpace",
    0x00000124: "TPM_CC_ChangeEPS",
    0x00000125: "TPM_CC_ChangePPS",
    0x00000126: "TPM_CC_Clear",
    0x00000127: "TPM_CC_ClearControl",
    0x00000128: "TPM_CC_ClockSet",
    0x00000129: "TPM_CC_HierarchyChangeAuth",
    0x0000012A: "TPM_CC_NV_DefineSpace",
    0x0000012B: "TPM_CC_PCR_Allocate",
    0x0000012C: "TPM_CC_PCR_SetAuthPolicy",
    0x0000012D: "TPM_CC_PP_Commands",
    0x0000012E: "TPM_CC_SetPrimaryPolicy",
    0x0000012F: "TPM_CC_FieldUpgradeStart",
    0x00000130: "TPM_CC_ClockRateAdjust",
    0x00000131: "TPM_CC_CreatePrimary",
    0x00000132: "TPM_CC_NV_GlobalWriteLock",
    0x00000133: "TPM_CC_GetCommandAuditDigest",
    0x00000134: "TPM_CC_NV_Increment",
    0x00000135: "TPM_CC_NV_SetBits",
    0x00000136: "TPM_CC_NV_Extend",
    0x00000137: "TPM_CC_NV_Write",
    0x00000138: "TPM_CC_NV_WriteLock",
    0x00000139: "TPM_CC_DictionaryAttackLockReset",
    0x0000013A: "TPM_CC_DictionaryAttackParameters",
    0x0000013B: "TPM_CC_NV_ChangeAuth",
    0x0000013C: "TPM_CC_PCR_Event",
    0x0000013D: "TPM_CC_PCR_Reset",
    0x0000013E: "TPM_CC_SequenceComplete",
    0x0000013F: "TPM_CC_SetAlgorithmSet",
    0x00000140: "TPM_CC_SetCommandCodeAuditStatus",
    0x00000141: "TPM_CC_FieldUpgradeData",
    0x00000142: "TPM_CC_IncrementalSelfTest",
    0x00000143: "TPM_CC_SelfTest",
    0x00000144: "TPM_CC_Startup",
    0x00000145: "TPM_CC_Shutdown",
    0x00000146: "TPM_CC_StirRandom",
    0x00000147: "TPM_CC_ActivateCredential",
    0x00000148: "TPM_CC_Certify",
    0x00000149: "TPM_CC_PolicyNV",
    0x0000014A: "TPM_CC_CertifyCreation",
    0x0000014B: "TPM_CC_Duplicate",
    0x0000014C: "TPM_CC_GetTime",
    0x0000014D: "TPM_CC_GetSessionAuditDigest",
    0x0000014E: "TPM_CC_NV_Read",
    0x0000014F: "TPM_CC_NV_ReadLock",
    0x00000150: "TPM_CC_ObjectChangeAuth",
    0x00000151: "TPM_CC_PolicySecret",
    0x00000152: "TPM_CC_Rewrap",
    0x00000153: "TPM_CC_Create",
    0x00000154: "TPM_CC_ECDH_ZGen",
    0x00000155: "TPM_CC_HMAC",
    0x00000156: "TPM_CC_Import",
    0x00000157: "TPM_CC_Load",
    0x00000158: "TPM_CC_Quote",
    0x00000159: "TPM_CC_RSA_Decrypt",
    0x0000015B: "TPM_CC_HMAC_Start",
    0x0000015C: "TPM_CC_SequenceUpdate",
    0x0000015D: "TPM_CC_Sign",
    0x0000015E: "TPM_CC_Unseal",
    0x00000161: "TPM_CC_PolicySigned",
    0x00000162: "TPM_CC_ContextLoad",
    0x00000163: "TPM_CC_ContextSave",
    0x00000164: "TPM_CC_ECDH_KeyGen",
    0x00000165: "TPM_CC_EncryptDecrypt",
    0x00000166: "TPM_CC_FlushContext",
    0x00000167: "TPM_CC_LoadExternal",
    0x00000168: "TPM_CC_MakeCredential",
    0x00000169: "TPM_CC_NV_ReadPublic",
    0x0000016A: "TPM_CC_PolicyAuthorize",
    0x0000016B: "TPM_CC_PolicyAuthValue",
    0x0000016C: "TPM_CC_PolicyCommandCode",
    0x0000016D: "TPM_CC_PolicyCounterTimer",
    0x0000016E: "TPM_CC_PolicyCpHash",
    0x0000016F: "TPM_CC_PolicyLocality",
    0x00000170: "TPM_CC_PolicyNameHash",
    0x00000171: "TPM_CC_PolicyOR",
    0x00000172: "TPM_CC_PolicyTicket",
    0x00000173: "TPM_CC_ReadPublic",
    0x00000174: "TPM_CC_RSA_Encrypt",
    0x00000175: "TPM_CC_StartAuthSession",
    0x00000176: "TPM_CC_VerifySignature",
    0x00000177: "TPM_CC_ECC_Parameters",
    0x00000178: "TPM_CC_FirmwareRead",
    0x00000179: "TPM_CC_GetCapability",
    0x0000017A: "TPM_CC_GetRandom",
    0x0000017B: "TPM_CC_GetTestResult",
    0x0000017C: "TPM_CC_Hash",
    0x0000017D: "TPM_CC_PCR_Read",
    0x0000017E: "TPM_CC_PolicyPCR",
    0x0000017F: "TPM_CC_PolicyRestart",
    0x00000180: "TPM_CC_ReadClock",
    0x00000181: "TPM_CC_PCR_Extend",
    0x00000182: "TPM_CC_PCR_SetAuthValue",
    0x00000183: "TPM_CC_NV_Certify",
    0x00000185: "TPM_CC_EventSequenceComplete",
    0x00000186: "TPM_CC_HashSequenceStart",
    0x00000187: "TPM_CC_PolicyPhysicalPresence",
    0x00000188: "TPM_CC_PolicyDuplicationSelect",
    0x00000189: "TPM_CC_PolicyGetDigest",
    0x0000018A: "TPM_CC_TestParms",
    0x0000018B: "TPM_CC_Commit",
    0x0000018C: "TPM_CC_PolicyPassword",
    0x0000018D: "TPM_CC_ZGen_2Phase",
    0x0000018E: "TPM_CC_EC_Ephemeral",
    0x0000018F: "TPM_CC_PolicyNvWritten",
    0x00000190: "TPM_CC_PolicyTemplate",
    0x00000191: "TPM_CC_CreateLoaded",
    0x00000192: "TPM_CC_PolicyAuthorizeNV",
    0x00000193: "TPM_CC_EncryptDecrypt2"
}

let TPM_ST = {
    0x00C4: "TPM_ST_RSP_COMMAND",
    0X8000: "TPM_ST_NULL",
    0x8001: "TPM_ST_NO_SESSIONS",
    0x8002: "TPM_ST_SESSIONS",
    0x8014: "TPM_ST_ATTEST_NV",
    0x8015: "TPM_ST_ATTEST_COMMAND_AUDIT",
    0x8016: "TPM_ST_ATTEST_SESSION_AUDIT",
    0x8017: "TPM_ST_ATTEST_CERTIFY",
    0x8018: "TPM_ST_ATTEST_QUOTE",
    0x8019: "TPM_ST_ATTEST_TIME",
    0x801A: "TPM_ST_ATTEST_CREATION",
    0x8021: "TPM_ST_CREATION",
    0x8022: "TPM_ST_VERIFIED",
    0x8023: "TPM_ST_AUTH_SECRET",
    0x8024: "TPM_ST_HASHCHECK",
    0x8025: "TPM_ST_AUTH_SIGNED",
    0x8029: "TPM_ST_FU_MANIFEST"
}

let FIDO_ALG_TO_COSE = {
    "ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW": {
        "kty": 2,
        "alg": -7,
        "crv": 1
    },
    "ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW": {
        "kty": 2,
        "alg": -7,
        "crv": 8
    },
    "ALG_SIGN_RSASSA_PSS_SHA256_RAW": {
        "kty": 3,
        "alg": -37
    },
    "ALG_SIGN_RSASSA_PSS_SHA384_RAW": {
        "kty": 3,
        "alg": -38
    },
    "ALG_SIGN_RSASSA_PSS_SHA512_RAW": {
        "kty": 3,
        "alg": -39
    },
    "ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW": {
        "kty": 3,
        "alg": -257
    },
    "ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW": {
        "kty": 3,
        "alg": -258
    },
    "ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW": {
        "kty": 3,
        "alg": -259
    },
    "ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW": {
        "kty": 3,
        "alg": -65535
    },
    "ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW": {
        "kty": 2,
        "alg": -35,
        "crv": 2
    },
    "ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW": {
        "kty": 2,
        "alg": -36,
        "crv": 3
    },
    "ALG_SIGN_ED25519_EDDSA_SHA256_RAW": {
        "kty": 1,
        "alg": -8,
        "crv": 6
    }
}

let COSE_TO_FIDO_ALG = {
    "kty:2,alg:-7,crv:1": "ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW",
    "kty:2,alg:-7,crv:8": "ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW",
    "kty:3,alg:-37": "ALG_SIGN_RSASSA_PSS_SHA256_RAW",
    "kty:3,alg:-38": "ALG_SIGN_RSASSA_PSS_SHA384_RAW",
    "kty:3,alg:-39": "ALG_SIGN_RSASSA_PSS_SHA512_RAW",
    "kty:3,alg:-257": "ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW",
    "kty:3,alg:-258": "ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW",
    "kty:3,alg:-259": "ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW",
    "kty:3,alg:-65535": "ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW",
    "kty:2,alg:-35,crv:2": "ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW",
    "kty:2,alg:-36,crv:3": "ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW",
    "kty:1,alg:-8,crv:6": "ALG_SIGN_ED25519_EDDSA_SHA256_RAW"
}

let TPM_MANUFACTURERS = {
    "id:414D4400": {
        "name":"AMD",
        "id": "AMD"
    },
    "id:41544D4C": {
        "name":"Atmel",
        "id": "ATML"
    },
    "id:4252434D": {
        "name":"Broadcom",
        "id": "BRCM"
    },
    "id:49424d00": {
        "name":"IBM",
        "id": "IBM"
    },
    "id:49465800": {
        "name":"Infineon",
        "id": "IFX"
    },
    "id:494E5443": {
        "name":"Intel",
        "id": "INTC"
    },
    "id:4C454E00": {
        "name":"Lenovo",
        "id": "LEN"
    },
    "id:4E534D20": {
        "name":"National Semiconductor",
        "id": "NSM"
    },
    "id:4E545A00": {
        "name":"Nationz",
        "id": "NTZ"
    },
    "id:4E544300": {
        "name":"Nuvoton Technology",
        "id": "NTC"
    },
    "id:51434F4D": {
        "name":"Qualcomm",
        "id": "QCOM"
    },
    "id:534D5343": {
        "name":"SMSC",
        "id": "SMSC"
    },
    "id:53544D20": {
        "name":"ST Microelectronics",
        "id": "STM"
    },
    "id:534D534E": {
        "name":"Samsung",
        "id": "SMSN"
    },
    "id:534E5300": {
        "name":"Sinosun",
        "id": "SNS"
    },
    "id:54584E00": {
        "name":"Texas Instruments",
        "id": "TXN"
    },
    "id:57454300": {
        "name":"Winbond",
        "id": "WEC"
    },
    "id:524F4343": {
        "name":"Fuzhouk Rockchip",
        "id": "ROCC"
    }
}