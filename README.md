# secp256k1authn

TypeScript toolkit for WebAuthn-style authentication that uses BIP39/BIP32 HD keys and the secp256k1 curve. One mnemonic → per-RP keys → challenge signatures that any backend can verify.

## Highlights
- **HD derivation**: `m/128273'/version'/deviceId'/rpIndex'/keyIndex` with `rpIndex = first31bits(SHA256(rpId))`.
- **Software authenticator**: works entirely in browser/Node, no hardware key.
- **Simple API**: `fromMnemonic`, `signChallenge`, `verifyChallengeSignature`, plus helper constants/types.

## How it works
1. User keeps a BIP39 mnemonic. `fromMnemonic` converts it to a BIP32 root.
2. To register with an RP (`rpId`), derive a key via `deriveAuthKey({ rpId, deviceId, keyIndex })`.
3. Registration sends `{ userId, rpId, publicKey }` to the server.
4. Authentication asks the server for a challenge, signs it with `signChallenge`, and the server verifies using the stored pubkey.

### Derivation details
```
m / PURPOSE_AUTH' / version' / deviceId' / rpIndex' / keyIndex
PURPOSE_AUTH = 128273 (🔑)
rpIndex = first_31_bits(SHA256(rpId))
```
All nodes except `keyIndex` are hardened; the final child is non-hardened to allow rotation.

## API
```ts
export async function fromMnemonic(mnemonic: string, passphrase?: string): Promise<RootContext>;

interface RootContext {
  deriveAuthKey(params: AuthKeyParams): Promise<DerivedKey>;
}

interface AuthKeyParams {
  rpId: string;
  deviceId?: number; // default 0
  keyIndex?: number; // default 0
  version?: number;  // default 0
}

interface DerivedKey {
  privKey: Uint8Array;   // 32 bytes
  pubKey: Uint8Array;    // compressed 33 bytes
  path: string;          // e.g. m/128273'/0'/0'/123456789'/0
}

export function signChallenge(privKey: Uint8Array, challenge: Uint8Array): Uint8Array;
export function verifyChallengeSignature(pubKey: Uint8Array, challenge: Uint8Array, signature: Uint8Array): boolean;
```

## Usage examples
### Browser: store mnemonic, derive key, register
```ts
import { fromMnemonic } from "secp256k1authn";

const MNEMONIC_KEY = "secp256k1authn:mnemonic";
function loadMnemonic(): string {
  const mnemonic = localStorage.getItem(MNEMONIC_KEY);
  if (!mnemonic) throw new Error("no mnemonic stored");
  return mnemonic;
}

async function register() {
  const userId = "user123";
  const rpId = "auth.openpleb.io";
  const mnemonic = loadMnemonic();

  const ctx = await fromMnemonic(mnemonic);
  const authKey = await ctx.deriveAuthKey({ rpId, deviceId: 0, keyIndex: 0 });
  const pubHex = Buffer.from(authKey.pubKey).toString("hex");

  await fetch("https://auth.openpleb.io/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ userId, rpId, publicKey: pubHex }),
  });
}
```

### Browser: authenticate
```ts
import { fromMnemonic, signChallenge } from "secp256k1authn";

async function authenticate() {
  const userId = "user123";
  const rpId = "auth.openpleb.io";
  const mnemonic = loadMnemonic();

  const cRes = await fetch("https://auth.openpleb.io/api/auth/challenge", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ userId, rpId }),
  });
  const { challenge } = await cRes.json();

  const ctx = await fromMnemonic(mnemonic);
  const authKey = await ctx.deriveAuthKey({ rpId, deviceId: 0, keyIndex: 0 });

  const challengeBytes = new TextEncoder().encode(challenge);
  const sig = signChallenge(authKey.privKey, challengeBytes);
  const sigHex = Buffer.from(sig).toString("hex");

  const vRes = await fetch("https://auth.openpleb.io/api/auth/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ userId, rpId, challenge, signature: sigHex }),
  });

  console.log(await vRes.json());
}
```

### Server: verify
```ts
import express from "express";
import { verifyChallengeSignature } from "secp256k1authn";

const app = express();
app.use(express.json());
const authKeys = new Map<string, { rpId: string; publicKey: string }>();
const challenges = new Map<string, string>();

app.post("/api/auth/challenge", (req, res) => {
  const { userId, rpId } = req.body;
  const challenge = crypto.randomUUID();
  challenges.set(`${userId}:${rpId}`, challenge);
  res.json({ challenge });
});

app.post("/api/auth/verify", (req, res) => {
  const { userId, rpId, challenge, signature } = req.body;
  const key = authKeys.get(`${userId}:${rpId}`);
  const expected = challenges.get(`${userId}:${rpId}`);
  if (!key || expected !== challenge) {
    return res.status(400).json({ error: "invalid challenge" });
  }
  challenges.delete(`${userId}:${rpId}`);

  const msgBytes = new TextEncoder().encode(challenge);
  const pubBytes = Buffer.from(key.publicKey, "hex");
  const sigBytes = Buffer.from(signature, "hex");

  const ok = verifyChallengeSignature(pubBytes, msgBytes, sigBytes);
  if (!ok) return res.status(401).json({ ok: false, error: "invalid sig" });
  res.json({ ok: true });
});
```

## Testing & building
```bash
npm install
npm run test    # vitest run
npm run typecheck
npm run build   # tsup bundle + dts
```

## Notes
- Keep mnemonics secure; treat derived keys as hot wallet secrets.
- Challenge strings must be unique per request, expire quickly, and never be reused.
- Mnemonic compromise leaks all derived keys (auth + any other purpose).
