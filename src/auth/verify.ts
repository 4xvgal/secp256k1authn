
import * as secp from "@noble/secp256k1";
import { sha256Bytes } from "../utils/hash.js";

/**
 * Verify a challenge signature using the public key and the provided signature.
 * Message bytes are hashed before signing to match verify().
 * returns a boolean
 */

export async function verifyChallengeSignature(
    pubKey:Uint8Array,
    message:Uint8Array,
    signature: Uint8Array,
): Promise<boolean> {
    const msgHash = sha256Bytes(message);
    return secp.verify(signature, msgHash, pubKey);
}

