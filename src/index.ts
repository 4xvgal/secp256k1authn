import type { AuthKeyParams, DerivedKey, RootContext } from "./types.js";

import { deriveAuthKeyFromRoot } from "./auth/derive.js";
import { rootFromSeed } from "./hd/bip32.js";
import { mnemonicToSeed } from "./hd/mnemonic.js";

/**
 * Build a RootContext from a mnemonic (and optional passphrase).
 * The returned context can deterministically derive auth keys for any RP.
 */
export async function fromMnemonic(
  mnemonic: string,
  passphrase = "",
): Promise<RootContext> {
  const seed = await mnemonicToSeed(mnemonic, passphrase);
  const root = rootFromSeed(seed);

  return {
    deriveAuthKey(params: AuthKeyParams): Promise<DerivedKey> {
      return deriveAuthKeyFromRoot(root, params);
    },
  };
}

export * from "./auth/sign.js";
export * from "./auth/verify.js";
export * from "./constants.js";
export * from "./types.js";
