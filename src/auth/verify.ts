
import * as secp from "@noble/secp256k1";
import { sha256Bytes } from "../utils/hash.js";

/**
 * Verify a challenge signature using the derived public key.
 * Returns true only when the signature matches the message hash.
 */
export function verifyChallengeSignature(
  pubKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  const msgHash = sha256Bytes(message);
  return secp.verify(signature, msgHash, pubKey);
}
