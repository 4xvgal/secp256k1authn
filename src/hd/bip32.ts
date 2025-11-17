import { HDKey } from "@scure/bip32";

/**
 * Create an HD root node from a BIP39-derived seed.
 */
export function rootFromSeed(seed: Uint8Array): HDKey {
  return HDKey.fromMasterSeed(seed);
}
