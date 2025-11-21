import { describe, expect, it } from "vitest";

import { makeAuthPath } from "../src/hd/path.js";
import { hashToIndex, sha256Bytes } from "../src/utils/hash.js";

describe("hash utilities", () => {
  it("hashToIndex is deterministic and within 31-bit range", () => {
    const rp = "auth.openpleb.io";
    const first = hashToIndex(rp);
    const second = hashToIndex(rp);

    expect(first).toBe(second);
    expect(first).toBeGreaterThanOrEqual(0);
    expect(first).toBeLessThan(0x80000000);
  });

  it("sha256Bytes matches expected digest length", () => {
    const digest = sha256Bytes("hello world");
    expect(digest).toBeInstanceOf(Uint8Array);
    expect(digest.length).toBe(32);
  });
});

describe("makeAuthPath", () => {
  it("returns hardened indices and formatted path", () => {
    const rpIndex = 123456789;
    const { path, indices } = makeAuthPath(rpIndex, 2, 5, 1);

    expect(path).toBe("m/128273'/1'/2'/123456789'/5'");
    expect(indices).toHaveLength(5);
    expect(indices[0]).toBeGreaterThanOrEqual(0x80000000);
    expect(indices[3]).toBe(rpIndex + 0x80000000);
    expect(indices[4]).toBe(5);
  });
});
