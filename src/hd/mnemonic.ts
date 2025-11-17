import * as bip39 from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";

/**
 * Convert a BIP39 mnemonic into a seed buffer.
 * Validates mnemonics against the English wordlist before deriving.
 */
export async function mnemonicToSeed(
  mnemonic: string,
  passphrase = "",
): Promise<Uint8Array> {
  if (!bip39.validateMnemonic(mnemonic, wordlist)) {
    throw new Error("Invalid mnemonic");
  }

  return bip39.mnemonicToSeedSync(mnemonic, passphrase);
}
