# @efficimo/cipher

[![npm version](https://img.shields.io/npm/v/@efficimo/cipher)](https://www.npmjs.com/package/@efficimo/cipher)
[![license](https://img.shields.io/npm/l/@efficimo/cipher)](./LICENSE)
[![types](https://img.shields.io/npm/types/@efficimo/cipher)](https://www.npmjs.com/package/@efficimo/cipher)

Cryptographic primitives for the browser and Node.js — AES-256-GCM vaults, RSA-OAEP key wrapping, PBKDF2 key derivation and WebAuthn PRF, with an observable lock state.

Built on the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). No external crypto dependencies.

## Installation

```bash
npm install @efficimo/cipher
```

`@efficimo/observable` is a peer dependency — `AESVault` and `RSAKeyPair` expose their state through it:

```bash
npm install @efficimo/observable
```

## Usage

### AESVault — symmetric encryption with observable lock state

`AESVault` holds an AES-256-GCM key in memory and exposes an `ObservableValue<boolean>` that components can subscribe to — no polling, no manual event listeners.

```ts
import { AESVault } from "@efficimo/cipher";

const vault = await AESVault.generate();

vault.isUnlocked.subscribe((unlocked) => {
  console.log("vault is", unlocked ? "open" : "locked");
}); // fires immediately with true

const blob = await vault.encrypt("top secret"); // base64: IV followed by ciphertext
await vault.decrypt(blob); // "top secret"

vault.lock(); // → subscriber fires with false
await vault.encrypt("anything"); // throws: AESVault is locked
```

`lock()` is one-way: it drops the key, it does not stash it away. To work with the vault again, build a new one from the key material — `AESVault.import()`, `AESVault.fromKey()` or `RSAKeyPair.unwrapKey()`.

A key can be moved between vaults, as long as it was generated as extractable:

```ts
const exported = await vault.export(); // base64 raw key
const clone = await AESVault.import(exported);
```

### Password-derived vaults

```ts
import { AESVault, deriveKey, generateSalt } from "@efficimo/cipher";

const salt = generateSalt();
const key = await deriveKey("my-passphrase", salt);
const vault = AESVault.fromKey(key);

const blob = await vault.encrypt("sensitive data");
```

The salt is not secret, but you need it to re-derive the same key — store it next to the ciphertext:

```ts
const stored = { salt: btoa(String.fromCharCode(...salt)), blob };
```

Keys returned by `deriveKey()` are non-extractable, so `export()` on such a vault rejects with `key is not extractable`. Use `AESVault.generate()` when the key has to leave the vault.

### Key rotation

```ts
const oldVault = AESVault.fromKey(await deriveKey("old-passphrase", oldSalt));

const newSalt = generateSalt();
const newVault = AESVault.fromKey(await deriveKey("new-passphrase", newSalt));

const rotated = await newVault.encrypt(await oldVault.decrypt(blob));
oldVault.lock();
```

### RSAKeyPair — key wrapping and portable private keys

`RSAKeyPair` encrypts short payloads directly, and wraps an `AESVault`'s key so that bulk data stays under AES while only the key travels under RSA.

```ts
import { AESVault, RSAKeyPair } from "@efficimo/cipher";

const pair = await RSAKeyPair.generate();
const vault = await AESVault.generate();
const blob = await vault.encrypt("bulk data");

// wrap the AES key under the RSA public key
const wrapped = await pair.wrapKey(vault);

// later, wherever the private key is available
const restored = await pair.unwrapKey(wrapped);
await restored.decrypt(blob); // "bulk data"
```

The private key can be persisted under a password and reloaded on top of a public-only pair:

```ts
const locked = await pair.lockPrivateKey("passphrase"); // { salt, iv, wrappedKey }

const reopened = await RSAKeyPair.fromPublicKey(pair.publicKey);
reopened.hasPrivateKey.getValue(); // false

await reopened.unlockPrivateKey(locked, "passphrase");
reopened.hasPrivateKey.getValue(); // true → subscribers fire
```

`encrypt()` goes through RSA-OAEP with a 2048-bit modulus and SHA-256, which caps a single payload at **190 bytes**. Anything larger belongs in an `AESVault` whose key you wrap with `wrapKey()`.

### The `Cipher` interface

`AESVault`, `RSAKeyPair` and `FileCipher` all implement `Cipher<string, string>`, so you can type parameters against the capability rather than the implementation:

```ts
import type { Cipher } from "@efficimo/cipher";

async function saveNote(cipher: Cipher, text: string) {
  return cipher.encrypt(text);
}
```

`FileCipher` wraps any `Cipher` — a thin, named layer for document payloads:

```ts
import { FileCipher } from "@efficimo/cipher";

const file = FileCipher.from(vault);
const blob = await file.encrypt(JSON.stringify(doc));
```

### WebAuthn PRF — biometric key derivation

Imported from `@efficimo/cipher/webauthn`. The same biometric on the same device always produces the same `CryptoKey` — without ever storing the key.

```ts
import { AESVault } from "@efficimo/cipher";
import { BiometricAuth, isBiometricSupported } from "@efficimo/cipher/webauthn";

if (await isBiometricSupported()) {
  const auth = new BiometricAuth();

  // First time: register
  const credential = await auth.register({ userId: "u1", userName: "alice" });

  // Subsequent visits: authenticate → open a vault on the derived key
  const key = await auth.authenticate(credential.id);
  const vault = AESVault.fromKey(key);

  const blob = await vault.encrypt("biometric-protected data");
}
```

Credential metadata (ID, userName) is stored in `localStorage`. The key itself is never stored.

> **Browser support (PRF extension):** Chrome 116+, Edge 116+, Safari 17.4+. Firefox is not supported. Always call `isBiometricSupported()` before showing a biometric option, and fall back to password-based `deriveKey()` otherwise.

## API

### Core — `@efficimo/cipher`

```ts
function generateSalt(): Uint8Array

function deriveKey(
  password: string,
  salt    : Uint8Array,
  options ?: { iterations?: number; hash?: "SHA-256" | "SHA-512" }
): Promise<CryptoKey>

class AESVault implements Cipher<string, string> {
  constructor(key: CryptoKey)

  static generate(extractable?: boolean): Promise<AESVault>        // default: true
  static import(base64: string, extractable?: boolean): Promise<AESVault>
  static fromKey(key: CryptoKey): AESVault

  readonly isUnlocked: ObservableValue<boolean>

  lock(): void                                  // drops the key, emits false
  export(): Promise<string>                     // base64 raw key (extractable keys only)
  encrypt(data: string): Promise<string>        // base64: IV + ciphertext
  decrypt(blob: string): Promise<string>
}

class RSAKeyPair implements Cipher<string, string> {
  static generate(): Promise<RSAKeyPair>                    // RSA-OAEP 2048, SHA-256
  static fromPublicKey(jwk: JsonWebKey): Promise<RSAKeyPair>

  readonly publicKey     : JsonWebKey
  readonly hasPrivateKey : ObservableValue<boolean>

  encrypt(data: string): Promise<string>        // ≤ 190 bytes
  decrypt(blob: string): Promise<string>

  wrapKey(vault: AESVault): Promise<string>
  unwrapKey(wrapped: string): Promise<AESVault>

  lockPrivateKey(password: string): Promise<WrappedPrivateKey>
  unlockPrivateKey(
    params      : WrappedPrivateKey,
    password    : string,
    extractable?: boolean                       // default: false
  ): Promise<void>
}

class FileCipher implements Cipher<string, string> {
  static from(cipher: Cipher<string, string>): FileCipher

  encrypt(content: string): Promise<string>
  decrypt(blob: string): Promise<string>
}
```

### WebAuthn — `@efficimo/cipher/webauthn`

```ts
function isBiometricSupported(): Promise<boolean>

class BiometricAuth {
  register(options: {
    userId      : string
    userName    : string
    displayName?: string
    rpName     ?: string
  }): Promise<CredentialInfo>

  authenticate(credentialId: string): Promise<CryptoKey>
  listCredentials(): CredentialInfo[]
  removeCredential(credentialId: string): void
}
```

### Types

```ts
interface Cipher<TData = string, TPayload = string> {
  encrypt(data: TData): Promise<TPayload>
  decrypt(payload: TPayload): Promise<TData>
}

interface WrappedPrivateKey {
  salt      : string   // base64 — PBKDF2 salt
  iv        : string   // base64 — AES-GCM initialisation vector
  wrappedKey: string   // base64 — PKCS8 private key, wrapped
}

interface KeyDerivationOptions {
  iterations?: number                    // default: 600_000
  hash      ?: "SHA-256" | "SHA-512"     // default: "SHA-256"
}

interface CredentialInfo {
  id         : string  // credential ID (base64url)
  userName   : string
  displayName: string
  createdAt  : number  // Unix timestamp
}
```

## Security notes

- **PBKDF2 iterations:** 600 000 (OWASP 2024 recommendation), for both `deriveKey()` and `lockPrivateKey()`.
- **Derived keys are non-extractable:** `deriveKey()` sets `extractable: false` — they cannot leave SubtleCrypto.
- **IV is never reused:** every `encrypt()` draws a fresh 96-bit IV from `crypto.getRandomValues()` and prefixes it to the ciphertext.
- **Keys stay out of the public API:** vault keys live in a module-level `WeakMap`, never as a property — `lock()` deletes the entry.
- **PRF salt is fixed per application:** the same eval salt ensures deterministic key derivation across sessions.
- **Broadcasts / shared secrets:** this library handles single-recipient encryption. For group or broadcast scenarios, symmetric key distribution is the caller's responsibility.

## License

MIT
