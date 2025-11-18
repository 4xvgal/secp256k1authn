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

    const ok = verifyChallengeSignature(pubKey, challengeBytes, signature);
    expect(ok).toBe(true);

    const tampered = new Uint8Array(signature);
    if (tampered.length > 0) {
      tampered.set([tampered[0] ^ 0xff], 0);
    }

    const fail = verifyChallengeSignature(pubKey, challengeBytes, tampered);
    expect(fail).toBe(false);
  });
});
