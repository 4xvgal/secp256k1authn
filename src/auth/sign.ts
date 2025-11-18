import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import * as secp from "@noble/secp256k1";

import { sha256Bytes } from "../utils/hash.js";

if (!secp.etc.hmacSha256Sync) {
  secp.etc.hmacSha256Sync = (key, ...msgs) =>
    hmac(sha256, key, secp.etc.concatBytes(...msgs));
}

/**
 * Sign a challenge using a derived private key.
 * Message bytes are hashed before signing to match verify().
 * Returns a compact 64-byte signature (r||s).
 */
export function signChallenge(
  privKey: Uint8Array,
  message: Uint8Array,
): Uint8Array {
  const msgHash = sha256Bytes(message);
  const signature = secp.sign(msgHash, privKey);
  return signature.toCompactRawBytes();
}
