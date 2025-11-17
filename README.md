# secp256k1authn

`secp256k1authn` is a TypeScript library for **WebAuthn-style public-key authentication using secp256k1 and HD keys (BIP39/BIP32)**.

It is designed to:

- Work with a **software authenticator inside the browser** (no physical FIDO key required).
- Derive per-site keys from a **single BIP39 mnemonic** using **BIP32 HD derivation**.
- Follow the **core ideas of WebAuthn/FIDO2** (public-key per RP, challenge–response, no shared secrets), but:
  - Use **secp256k1** instead of `secp256r1`.
  - Use **HD keys** (one mnemonic → many RP keys).
- Be compatible with other systems (e.g. **Cashu**), so the same mnemonic can be reused with **different derivation paths**.

---

## 1. Why WebAuthn as a reference?

We borrow the key ideas from WebAuthn/FIDO2 but adapt them:

- **Per-RP key pairs**  
  Each web origin (RP ID, like `auth.openpleb.io`) gets a unique key pair.  
  → Avoids cross-site correlation and central shared secrets.

- **Challenge–response**  
  Server issues a random challenge; client signs it with its private key.  
  → Prevents replay attacks; server only stores public keys.

- **Authenticator separation**  
  WebAuthn distinguishes:
  - Client (browser)
  - Authenticator (hardware key, OS, etc.)
  We model the **software authenticator** inside the browser (HD key engine).

Differences vs actual WebAuthn:

- WebAuthn mandates `secp256r1`, we use **secp256k1** (Bitcoin/Ethereum curve).
- WebAuthn requires secure hardware/OS authenticators; we allow **pure JS software**.
- WebAuthn has a rich CTAP/WebAuthn API; our library exposes a **simple TS API**:
  - `fromMnemonic(...) → RootContext`
  - `RootContext.deriveAuthKey(...)`
  - `signChallenge(...)`, `verifyChallengeSignature(...)`

---

## 2. Cryptographic design

### 2.1. High-level

1. User has a **BIP39 mnemonic** (same style as Bitcoin wallet).
2. We derive a **BIP32 master key** from the mnemonic.
3. For each RP (e.g. `auth.openpleb.io`), we derive a unique **secp256k1 key pair** using:
   - A fixed **purpose’** value (based on 🔑 emoji).
   - A version.
   - A device ID.
   - A RP-specific index (hash of `rpId`).
   - A key index for rotation.

The same mnemonic can also be used for **Cashu** or other protocols by using different **purpose’** values and derivation paths.

### 2.2. Purpose’

We use the 🔑 emoji for the auth purpose:

- 🔑 (Key emoji)
  - Codepoint: `U+1F511`
  - Decimal: `128273`

In BIP32, indices are 32-bit unsigned integers. Hardened children are:

```text
child_index' = child_index + 0x80000000
````

So:

```text
PURPOSE_AUTH = 128273        // raw purpose value
PURPOSE_AUTH_HARDENED = 128273 + 0x80000000
```

We always use the **hardened** form internally, but in the path notation we write `128273'`.

### 2.3. Derivation path

We define the auth derivation path as:

```text
m / PURPOSE_AUTH' / version' / deviceId' / rpIndex' / keyIndex
```

Where:

* `PURPOSE_AUTH` = `128273` (🔑)
* `version` = protocol version (start with `0`)
* `deviceId` = integer identifying this device (0, 1, 2, ...)
* `rpIndex` = deterministic index derived from `rpId` (domain-like string)
* `keyIndex` = non-hardened index for key rotation (0, 1, 2, ...)

#### rpIndex calculation

```ts
rpIndex = first_31_bits_of(SHA256(rpId))
```

* `rpId`: e.g. `"auth.openpleb.io"`
* We take SHA-256, read the first 32 bits, mask to 31 bits (`& 0x7fffffff`).
* Then we harden it: `rpIndex' = rpIndex + 0x80000000`.

This ensures:

* Each RP gets a separate subtree.
* RP index is deterministic but not trivially guessable from path alone.

---

## 3. Protocol flows

### 3.1. Registration (one-time per RP per device)

Participants:

* **Browser**: client app
* **Software Authenticator** (inside browser): `secp256k1authn` + HD keys
* **Server**: backend API

Flow:

1. Browser → Authenticator:
   “Derive key pair for this RP” (`rpId`, `deviceId`, `keyIndex`).
2. Authenticator:

   * Uses BIP39 mnemonic → BIP32 root.
   * Computes path `m / PURPOSE_AUTH' / version' / deviceId' / rpIndex' / keyIndex`.
   * Derives `privKey`, `pubKey`.
3. Browser → Server:
   `userId`, `rpId`, `pubKey`.
4. Server:

   * Saves `userId + rpId → pubKey`.
   * Returns success.

### 3.2. Authentication (login)

1. Browser → Server: “Start auth for userId, rpId.”
2. Server:

   * Generates random `challenge`.
   * Stores `challenge` mapped to `userId + rpId`.
   * Returns `challenge`.
3. Browser:

   * Uses same HD path → same `privKey` for `(rpId, deviceId, keyIndex)`.
   * Computes `signature = Sign(privKey, challenge)`.
4. Browser → Server:
   `userId`, `rpId`, `challenge`, `signature`.
5. Server:

   * Loads stored `pubKey` for `userId + rpId`.
   * Validates that `challenge` matches the stored one (one-time use).
   * Verifies `signature` using `pubKey` and `challenge`.
   * If valid → authentication success.

---

## 4. Public API design

### 4.1. Types

```ts
export interface DerivedKey {
  privKey: Uint8Array;  // 32 bytes
  pubKey: Uint8Array;   // compressed 33 bytes (recommended)
  path: string;         // BIP32 path string, e.g. "m/128273'/0'/0'/123456789'/0"
}

export interface AuthKeyParams {
  rpId: string;        // e.g. "auth.openpleb.io"
  deviceId?: number;   // default: 0
  keyIndex?: number;   // default: 0
  version?: number;    // default: 0
}

export interface RootContext {
  deriveAuthKey(params: AuthKeyParams): Promise<DerivedKey> | DerivedKey;
}
```

### 4.2. Top-level functions

```ts
// Initialize from BIP39 mnemonic
export async function fromMnemonic(
  mnemonic: string,
  passphrase?: string,
): Promise<RootContext>;

// EC helpers
export async function signChallenge(
  privKey: Uint8Array,
  message: Uint8Array,
): Promise<Uint8Array>;

export async function verifyChallengeSignature(
  pubKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean>;
```

`message` can be either the raw challenge bytes or a pre-hashed value, depending on how you define it internally; be consistent.

---

## 5. Project structure

```text
secp256k1authn/
  package.json
  tsconfig.json
  README.md

  src/
    index.ts
    constants.ts
    types.ts

    hd/
      mnemonic.ts     // BIP39 wrapper
      bip32.ts        // BIP32 wrapper (fromSeed, deriveChild)
      path.ts         // path building: PURPOSE_AUTH', rpIndex', ...

    auth/
      derive.ts       // deriveAuthKeyFromRoot(root, params)
      sign.ts         // signChallenge(privKey, msg)
      verify.ts       // verifyChallengeSignature(pubKey, msg, sig)

    utils/
      hash.ts         // SHA-256, hashToIndex(rpId)
      bytes.ts        // hex <-> Uint8Array helper

  test/
    auth.test.ts
    hd.test.ts
```

### 5.1. constants.ts

```ts
export const PURPOSE_AUTH = 128_273;      // 🔑
export const DEFAULT_AUTH_VERSION = 0;
export const HARDENED_OFFSET = 0x80000000;
```

### 5.2. hd/mnemonic.ts

Use `@scure/bip39`:

```ts
import * as bip39 from "@scure/bip39";
import { english } from "@scure/bip39/wordlists/english";

export async function mnemonicToSeed(
  mnemonic: string,
  passphrase = "",
): Promise<Uint8Array> {
  // optional: validate mnemonic
  if (!bip39.validateMnemonic(mnemonic, english)) {
    throw new Error("Invalid mnemonic");
  }
  return bip39.mnemonicToSeedSync(mnemonic, passphrase);
}
```

### 5.3. hd/bip32.ts

Use `@scure/bip32`:

```ts
import { HDKey } from "@scure/bip32";

export function rootFromSeed(seed: Uint8Array): HDKey {
  return HDKey.fromMasterSeed(seed);
}
```

### 5.4. utils/hash.ts

Use `@noble/hashes`.

```ts
import { sha256 } from "@noble/hashes/sha256";

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
```

### 5.5. hd/path.ts

```ts
import { HARDENED_OFFSET, PURPOSE_AUTH, DEFAULT_AUTH_VERSION } from "../constants";

export function makeAuthPath(
  rpIndex: number,
  deviceId = 0,
  keyIndex = 0,
  version = DEFAULT_AUTH_VERSION,
): { path: string; indices: number[] } {
  const purposeH = PURPOSE_AUTH + HARDENED_OFFSET;
  const versionH = version + HARDENED_OFFSET;
  const deviceH  = deviceId + HARDENED_OFFSET;
  const rpH      = rpIndex + HARDENED_OFFSET;
  const normal   = keyIndex;

  const indices = [purposeH, versionH, deviceH, rpH, normal];

  const path =
    `m/${PURPOSE_AUTH}'/${version}'/${deviceId}'/${rpIndex}'/${keyIndex}`;

  return { path, indices };
}
```

### 5.6. auth/derive.ts

Using `@noble/secp256k1`:

```ts
import { HDKey } from "@scure/bip32";
import * as secp from "@noble/secp256k1";
import { AuthKeyParams, DerivedKey } from "../types";
import { hashToIndex } from "../utils/hash";
import { makeAuthPath } from "../hd/path";

export async function deriveAuthKeyFromRoot(
  root: HDKey,
  params: AuthKeyParams,
): Promise<DerivedKey> {
  const { rpId, deviceId = 0, keyIndex = 0, version } = params;

  const rpIndex = hashToIndex(rpId);
  const { path, indices } = makeAuthPath(rpIndex, deviceId, keyIndex, version);

  let node: HDKey = root;
  for (const i of indices) {
    node = node.deriveChild(i);
  }

  if (!node.privateKey) {
    throw new Error("No private key derived (public-only root?)");
  }

  const privKey = node.privateKey;
  const pubKey = secp.getPublicKey(privKey, true); // compressed

  return { privKey, pubKey, path };
}
```

### 5.7. auth/sign.ts and verify.ts

```ts
// auth/sign.ts
import * as secp from "@noble/secp256k1";
import { sha256Bytes } from "../utils/hash";

export async function signChallenge(
  privKey: Uint8Array,
  message: Uint8Array,
): Promise<Uint8Array> {
  const msgHash = sha256Bytes(message);
  const sig = await secp.sign(msgHash, privKey, { der: true });
  return sig;
}
```

```ts
// auth/verify.ts
import * as secp from "@noble/secp256k1";
import { sha256Bytes } from "../utils/hash";

export async function verifyChallengeSignature(
  pubKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  const msgHash = sha256Bytes(message);
  return secp.verify(signature, msgHash, pubKey);
}
```

### 5.8. index.ts

```ts
import { mnemonicToSeed } from "./hd/mnemonic";
import { rootFromSeed } from "./hd/bip32";
import { AuthKeyParams, RootContext, DerivedKey } from "./types";
import { deriveAuthKeyFromRoot } from "./auth/derive";

export async function fromMnemonic(
  mnemonic: string,
  passphrase = "",
): Promise<RootContext> {
  const seed = await mnemonicToSeed(mnemonic, passphrase);
  const root = rootFromSeed(seed);

  return {
    async deriveAuthKey(params: AuthKeyParams): Promise<DerivedKey> {
      return deriveAuthKeyFromRoot(root, params);
    },
  };
}

export * from "./auth/sign";
export * from "./auth/verify";
export * from "./constants";
export * from "./types";
```

---

## 6. External dependencies

Recommended stack:

```jsonc
{
  "dependencies": {
    "@noble/secp256k1": "^X.Y.Z",   // secp256k1 ECC
    "@noble/hashes": "^X.Y.Z",     // SHA-256
    "@scure/bip32": "^X.Y.Z",      // BIP-32 HD
    "@scure/bip39": "^X.Y.Z"       // BIP-39 mnemonic
  },
  "devDependencies": {
    "typescript": "^5.x",
    "ts-node": "^10.x",
    "vitest": "^1.x",              // or jest
    "tsup": "^8.x"                 // or esbuild/rollup for bundling
  }
}
```

---

## 7. Usage examples

### 7.1. Browser: Registration

```ts
import { fromMnemonic } from "secp256k1authn";

const MNEMONIC_KEY = "secp256k1authn:mnemonic";

function loadMnemonic(): string {
  const m = localStorage.getItem(MNEMONIC_KEY);
  if (!m) throw new Error("no mnemonic stored");
  return m;
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

### 7.2. Browser: Authentication

```ts
import { fromMnemonic, signChallenge } from "secp256k1authn";

async function authenticate() {
  const userId = "user123";
  const rpId = "auth.openpleb.io";
  const mnemonic = loadMnemonic();

  // 1) Challenge 요청
  const cRes = await fetch("https://auth.openpleb.io/api/auth/challenge", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ userId, rpId }),
  });
  const { challenge } = await cRes.json();

  // 2) 키 파생
  const ctx = await fromMnemonic(mnemonic);
  const authKey = await ctx.deriveAuthKey({ rpId, deviceId: 0, keyIndex: 0 });

  // 3) 서명
  const challengeBytes = new TextEncoder().encode(challenge);
  const sig = await signChallenge(authKey.privKey, challengeBytes);
  const sigHex = Buffer.from(sig).toString("hex");

  // 4) 서버 검증 요청
  const vRes = await fetch("https://auth.openpleb.io/api/auth/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ userId, rpId, challenge, signature: sigHex }),
  });

  const result = await vRes.json();
  console.log(result);
}
```

### 7.3. Server: Verification (Node)

```ts
import express from "express";
import { verifyChallengeSignature } from "secp256k1authn";

const app = express();
app.use(express.json());

const authKeys = new Map<string, { rpId: string; publicKey: string }>();
const challenges = new Map<string, string>();

app.post("/api/auth/challenge", (req, res) => {
  const { userId, rpId } = req.body;
  // ... generate and store challenge ...
});

app.post("/api/auth/verify", async (req, res) => {
  const { userId, rpId, challenge, signature } = req.body;

  const key = authKeys.get(`${userId}:${rpId}`);
  const expected = challenges.get(`${userId}:${rpId}`);

  if (!key || !expected || expected !== challenge) {
    return res.status(400).json({ error: "invalid challenge" });
  }

  challenges.delete(`${userId}:${rpId}`);

  const msgBytes = new TextEncoder().encode(challenge);
  const pubBytes = Buffer.from(key.publicKey, "hex");
  const sigBytes = Buffer.from(signature, "hex");

  const ok = await verifyChallengeSignature(pubBytes, msgBytes, sigBytes);
  if (!ok) return res.status(401).json({ ok: false, error: "invalid sig" });

  return res.json({ ok: true });
});
```

---

## 8. Security notes

* **Mnemonic / seed security**

  * If used in the browser, protect against XSS.
  * Ideally encrypt mnemonic or derived keys with Web Crypto (not just localStorage plain).

* **Challenge**

  * Must be **unique per request** and **one-time**.
  * Should expire (e.g. within 1 minute).

* **Key reuse**

  * HD derivation ensures per-RP keys, but same mnemonic reused across:

    * Auth (`PURPOSE_AUTH`)
    * Cashu (`PURPOSE_CASHU`)
  * If mnemonic leaks, **all** derived keys (Auth + Cashu) are compromised.

* **Server compromise**

  * Server only stores public keys and challenges.
  * If server is compromised, attackers still do not get private keys.
