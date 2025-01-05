import { p1363ToDer } from "../libs/ecdsa-utils.js";
import { utils } from "./util.js";
import { validateRpId } from './validateRpId.js';

export async function handleGet(options, origin, auth) {
    console.log("handle get called");

    // TODO: Ask for user consent!
    const pw = await auth.getPassphrase();
    if (pw == null) {
        return;
    }

    if (!options.publicKey.allowCredentials || options.publicKey.allowCredentials.length < 1) {
        console.log("not our credential");
        return
    }

    const rootSecret = await getRootSecret(pw);

    const rpId = validateRpId(options.publicKey.rpId, origin);

    let validCredential = null;
    for (const credential of options.publicKey.allowCredentials) {
        const isValid = await validateCredentialId(rootSecret, rpId, new Uint8Array(credential.id));
        if (isValid) {
            validCredential = credential;
            break;
        }
    }

    if (!validCredential) {
        console.log("No valid credential found");
        return null;
    }

    // Now we know that we can rederive the key for this credential!
    const key = await deriveKeyPair(rootSecret, new Uint8Array(validCredential.id));

    const clientData = {
        type: "webauthn.get",
        challenge: new Uint8Array(options.publicKey.challenge).toBase64({ alphabet: "base64url", omitPadding: true }),
        origin: "https://" + rpId
    }

    const clientDataEnc = new TextEncoder().encode((JSON.stringify(clientData)))

    const clientDataHash = await utils.sha256(clientDataEnc);

    const authData = await buildAuthData(rpId, new Uint8Array(validCredential.id), key)
    const sigBase = new Uint8Array([
        ...authData,
        ...new Uint8Array(clientDataHash),
    ]);
    const p1363_signature = new Uint8Array(
        await crypto.subtle.sign(
            {
                name: "ECDSA",
                hash: { name: "SHA-256" },
            },
            key,
            sigBase,
        ),
    );

    const asn1Der_signature = p1363ToDer(p1363_signature);

    console.log("we signed a thing!")
    return {
        rawId: new Uint8Array(validCredential.id),
        id: new Uint8Array(validCredential.id).toBase64({ alphabet: "base64url", omitPadding: true }),
        type: "public-key",
        response: {
            signature: asn1Der_signature.buffer,
            clientDataJSON: clientDataEnc.buffer,
            authenticatorData: new Uint8Array([...authData]).buffer
        }
    };
}

export async function handleCreate(options, origin, auth) {
    console.log("handle create called");
    const pkOptions = options.publicKey;

    // TODO: Ask for user consent, populate user presence flag properly etc.
    const pw = await auth.getPassphrase();
    if (pw == null) {
        throw new Error("Not logged in");
    }

    const rootSecret = await getRootSecret(await auth.getPassphrase());

    const rpId = validateRpId(options.publicKey.rpId, origin);

    const rawCredentialId = await newCredentialIdForRp(rootSecret, rpId);
    const key = await deriveKeyPair(rootSecret, rawCredentialId);

    const authData = await buildAuthData(rpId, rawCredentialId, key)

    const responseData = {
        type: "webauthn.create",
        challenge: new Uint8Array(pkOptions.challenge).toBase64({ alphabet: "base64url", omitPadding: true }),
        origin: "https://" + rpId
    }

    const attestationObject = new Uint8Array(
        CBOR.encode({
            fmt: "none",
            attStmt: {},
            authData: new Uint8Array([...authData]),
        }),
    );

    console.log("keypair created")
    return {
        rawId: rawCredentialId,
        id: rawCredentialId.toBase64({ alphabet: "base64url", omitPadding: true }),
        type: "public-key",
        response: {
            attestationObject: attestationObject,
            clientDataJSON: new TextEncoder().encode((JSON.stringify(responseData))),

            clientExtensionResults: {},
        }
    };
}

async function buildAuthData(rpId, rawCredentialId, key) {
    const AAGUID = new Uint8Array([
        0xF6, 0x2D, 0x07, 0x75, 0xC0, 0x01, 0x47, 0x91,
        0xAC, 0x15, 0xAE, 0x66, 0x9D, 0x09, 0x9F, 0x6B
    ]);

    // Auth data will be: rpIdHash || flags || signCount || attestedCredentialData || extensions
    const authData = [];
    const rpIdHash = new Uint8Array(
        await utils.sha256(rpId),
    );
    authData.push(...rpIdHash);

    // TODO: Implement flags a bit more properly.
    // For example, we could request passphrase re-entry for user verification, and a pop-up confirmation for
    // user presence.
    // Right now, we say 0x5D = 01011101 = user present = true, RFU, user verified = true, backup eligible = true
    // backed up = true (don't forget your passphrase!), RFU, "attested credential data follows" = true
    // (I don't actually understand why it would ever _not_ follow, since that's the only place we can actually
    // provide the public key...? Maybe we can omit that for verification later?)
    authData.push(93);

    // Signature counter. Since this is a stateless implementation, providing a time-based
    // value would actually not add any security benefit.
    // All zero is allowed per WebAuthn spec (although it seems to be mandatory in FIDO)
    authData.push(...utils.numberToBEUint32(0))

    const attestedCredentialData = [];

    attestedCredentialData.push(...AAGUID);

    // credentialIdLength (BE Uint16) and credential Id
    attestedCredentialData.push(...utils.numberToBEUint16(rawCredentialId.length));
    attestedCredentialData.push(...rawCredentialId);

    const publicKeyJwk = await crypto.subtle.exportKey("jwk", key);
    // COSE format of the EC256 key
    const keyX = utils.b64UrlToU8(publicKeyJwk.x);
    const keyY = utils.b64UrlToU8(publicKeyJwk.y);

    // We only support ECDSA keys in P-256, so they all have a predictable length and structure,
    // based on the webauthn spec  (compare examples 9/10 in https://w3c.github.io/webauthn):
    // {  A5 - start of a map with 5 key/value pairs
    //     kty: "EC" => 1: 2 => 01 02
    //     alg: -7 (ECDSA w/ SHA-256) => 3: -7 => 03 26
    //     crv: 1 (P-256 a.k.a. secp256r1) -1: 1 => 20 01
    //     x: (pubKey.x) => -2:  Uint8[pubKey.x] => 21 (-2) 58 (uint8 array of length) 20 (32 bytes to follow) [pubKey.x]
    //     y: (pubKey.y) => -3:  Uint8[pubKey.y] => 22 (-3) 58 (uint8 array of length) 20 (32 bytes to follow) [pubKey.y]
    // }

    const coseBytes = new Uint8Array([
        ...[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20], ...keyX, 
        ...[0x22, 0x58, 0x20], ...keyY]);

    console.assert(coseBytes.length == 77, "COSE key length mismatch");

    // credential public key - convert to array from CBOR encoded COSE key
    attestedCredentialData.push(...coseBytes);

    authData.push(...attestedCredentialData);

    return authData;
}

export async function newCredentialIdForRp(rootSecret, rpId) {
    // The Credential ID is a function of
    // - the root secret (so that we can determine whether this is "our" credential when RPs are enumerating
    //     eligible credentials)
    // - the rpId (to scope it to a given RP for privacy), and
    // - a random input (to allow for multiple credentials per PR and to avoid confusion by having IDs be deterministic)

    // v0.1 format: credentialId = randomBytes (32 byte) || SHA-256("Brainchain v0.1 credential ID derivation" || randomBytes || rootSecret || rpId)

    const randomBytes = new Uint8Array(32);
    crypto.getRandomValues(randomBytes);

    const hashBuffer = await credentialIdHash(rootSecret, rpId, randomBytes);
    return new Uint8Array([...randomBytes, ...hashBuffer]);
}

export async function validateCredentialId(rootSecret, rpId, credentialId) {
    if (new Uint8Array(credentialId).length !== 64) {
        return false;
    }
    const randomBytes = credentialId.slice(0, 32);
    const inputHash = credentialId.slice(32);

    const calculatedHash = new Uint8Array(await credentialIdHash(rootSecret, rpId, randomBytes));

    return byteArraysEqual(calculatedHash, inputHash);
}

async function credentialIdHash(rootSecret, rpId, randomBytes) {
    const encoder = new TextEncoder();
    const wellKnownStringBytes = encoder.encode("Brainchain v0.1 credential ID derivation");
    const rpIdBytes = encoder.encode(rpId);

    const hashInput = new Uint8Array([...wellKnownStringBytes, ...randomBytes, ...rootSecret, ...rpIdBytes]);

    return new Uint8Array(await crypto.subtle.digest('SHA-256', hashInput));
}

const byteArraysEqual = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

async function deriveKeyPair(rootSecret, rawCredentialId) {
    // Technically not all 256 bit strings are valid P-256 private keys, but the probabilities
    // of this are negligible.
    const privateKey = await utils.sha256(new Uint8Array([...rootSecret, ...rawCredentialId]));

    // Subtle crypto does not allow importing random bytestrings as private ECDSA keys, so we
    // need to use another library to generate the public key from the private key
    const publicKey = nobleCurves.p256.getPublicKey(privateKey, false);
    const x = publicKey.slice(1, 33);
    const y = publicKey.slice(33, 65);

    // Fortunately JWK is relatively easy to hand-construct, and subtle crypto accepts that.
    const jwk = {
        crv: "P-256",
        d: privateKey.toBase64({ alphabet: "base64url", omitPadding: true }),
        kty: "EC",
        x: x.toBase64({ alphabet: "base64url", omitPadding: true }),
        y: y.toBase64({ alphabet: "base64url", omitPadding: true })
    }

    const key = await crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign"]
    );

    return key;
}

async function getRootSecret(passphrase) {
    // root secret = PBKDF2(passphrase, "Brainchain v0.1 well-known root secret derivation", 100000, 256)
    const encoder = new TextEncoder();
    const passphraseBytes = encoder.encode(passphrase);
    const saltBytes = encoder.encode("Brainchain v0.1 well-known root secret derivation");

    // First derive 32 bytes using PBKDF2
    const baseKey = await crypto.subtle.importKey(
        "raw",
        passphraseBytes,
        "PBKDF2",
        false,
        ["deriveBits"]
    );

    const rootSecret = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: saltBytes,
            iterations: 100000,
            hash: "SHA-256"
        },
        baseKey,
        256  // 32 bytes
    );

    return new Uint8Array(rootSecret);
}