import { describe, expect, it } from "vitest";

import { fromMnemonic } from "../src/index.js";

const TEST_MNEMONIC =
  "unaware nerve cat uncle fly among hobby hedgehog favorite zoo runway direct";

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

describe("deriveAuthKey", () => {
  it("returns deterministic keys for the same parameters", async () => {
    const ctx = await fromMnemonic(TEST_MNEMONIC);
    const params = { rpId: "auth.openpleb.io", deviceId: 0, keyIndex: 0 };

    const keyA = await ctx.deriveAuthKey(params);
    const keyB = await ctx.deriveAuthKey(params);
    expect(keyA.path).toBe(keyB.path);
    expect(toHex(keyA.pubKey)).toBe(toHex(keyB.pubKey));
    expect(toHex(keyA.privKey)).toBe(toHex(keyB.privKey));
  });

  it("derives distinct keys for different rpIds", async () => {
    const ctx = await fromMnemonic(TEST_MNEMONIC);

    const openpleb = await ctx.deriveAuthKey({ rpId: "auth.openpleb.io" });
    const example = await ctx.deriveAuthKey({ rpId: "example.com" });
    expect(openpleb.path).not.toBe(example.path);
    expect(toHex(openpleb.pubKey)).not.toBe(toHex(example.pubKey));
  });
});
