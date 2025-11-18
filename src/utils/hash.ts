import { sha256 } from "@noble/hashes/sha2";

export function sha256Bytes(data: Uint8Array | string): Uint8Array {
  const bytes =
    typeof data === "string" ? new TextEncoder().encode(data) : data;
  return sha256(bytes);
}

// 31-bit index from string
export function hashToIndex(input: string): number {
  const h = sha256Bytes(input);
  const view = new DataView(h.buffer, h.byteOffset, h.byteLength);
  const raw = view.getUint32(0, false); // big-endian
  const index = raw & 0x7fffffff;       // 0..2^31-1
  return index;
}