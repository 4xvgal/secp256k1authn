import { describe, expect, it } from "vitest";
import {
    fromMnemonic,
    signChallenge,
    verifyChallengeSignature,
} from "../src/index.js";

const TEST_MNEMONIC =
  "unaware nerve cat uncle fly among hobby hedgehog favorite zoo runway direct";
const TEST_RPID = "auth.example.com";
const TEST_MESSAGE =
  "Liberty is always freedom from the government. -Ludwig von Mises";

describe("sign/verify flow", () => {
  it("signs a challenge and verifies it with the derived pubKey", async () => {
    const ctx = await fromMnemonic(TEST_MNEMONIC);
    const { privKey, pubKey } = await ctx.deriveAuthKey({
      rpId: TEST_RPID,
      deviceId: 0,
      keyIndex: 0,
    });

    const challengeBytes = new TextEncoder().encode(TEST_MESSAGE);
    const signature = signChallenge(privKey, challengeBytes);
    console.log("signature:", Buffer.from(signature).toString("hex"));

    const ok = await verifyChallengeSignature(pubKey, challengeBytes, signature);
    console.log("verification result:", ok);
    expect(ok).toBe(true);

    const tampered = new Uint8Array(signature);
    if (tampered.length > 0) {
      tampered.set([tampered[0] ^ 0xff], 0);
      console.log("tampered signature:", Buffer.from(tampered).toString("hex"));
    }

    const fail = await verifyChallengeSignature(pubKey, challengeBytes, tampered);
    console.log("verification result (tampered):", fail);
    expect(fail).toBe(false);
  });
});
