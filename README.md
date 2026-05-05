# @efficimo/cipher

Cryptographic primitives for the browser and Node.js — AES-256-GCM encryption, PBKDF2 key derivation, WebAuthn PRF, and an observable vault that unlocks reactively.

Built on the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). No external crypto dependencies.

## Installation

```bash
npm install @efficimo/cipher
```

`@efficimo/observable` is a peer dependency required by `CipherVault`:

```bash
npm install @efficimo/observable
```

## Usage

### Symmetric encryption (password-based)

```ts
import { generateSalt, deriveKey, encrypt, decrypt } from "@efficimo/cipher";

const salt = generateSalt();
const key = await deriveKey("my-passphrase", salt);

const payload = await encrypt("sensitive data", key);
// { ciphertext: "...", iv: "...", version: 1 }

const result = await decrypt(payload, key);
new TextDecoder().decode(result); // "sensitive data"
```

To store and later re-derive the same key, attach the salt to the payload:

```ts
const stored = { ...payload, salt: btoa(String.fromCharCode(...salt)) };
```

### Key rotation

```ts
import { reEncrypt, deriveKey, generateSalt } from "@efficimo/cipher";

const newKey = await deriveKey("new-passphrase", generateSalt());
const rotated = await reEncrypt(payload, oldKey, newKey);
```

### CipherVault — observable unlock state

`CipherVault` wraps a key in memory and exposes an `ObservableValue<boolean>` that components can subscribe to — no polling, no manual event listeners.

```ts
import { CipherVault, deriveKey, generateSalt } from "@efficimo/cipher";

const vault = new CipherVault();

vault.isUnlocked.subscribe((unlocked) => {
  console.log("vault is", unlocked ? "open" : "locked");
});

const key = await deriveKey("passphrase", generateSalt());
vault.unlock(key); // → subscriber fires with true

const payload = await vault.encrypt("top secret");
const result  = await vault.decrypt(payload);

vault.lock(); // → subscriber fires with false
```

The `Cipher` interface is implemented by `CipherVault`, so you can type parameters against it:

```ts
import type { Cipher } from "@efficimo/cipher";

async function saveNote(cipher: Cipher, text: string) {
  return cipher.encrypt(text);
}
```

### WebAuthn PRF — biometric key derivation

Imported from `@efficimo/cipher/webauthn`. Same biometric on the same device always produces the same `CryptoKey` — without ever storing the key.

```ts
import { isBiometricSupported, BiometricAuth } from "@efficimo/cipher/webauthn";
import { CipherVault } from "@efficimo/cipher";

if (await isBiometricSupported()) {
  const auth  = new BiometricAuth();
  const vault = new CipherVault();

  // First time: register
  const credential = await auth.register({ userId: "u1", userName: "alice" });

  // Subsequent visits: authenticate → unlock vault
  const key = await auth.authenticate(credential.id);
  vault.unlock(key);

  const payload = await vault.encrypt("biometric-protected data");
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

function encrypt(data: string | ArrayBuffer, key: CryptoKey): Promise<EncryptedPayload>
function decrypt(payload: EncryptedPayload,  key: CryptoKey): Promise<ArrayBuffer>

function reEncrypt(
  payload: EncryptedPayload,
  oldKey : CryptoKey,
  newKey : CryptoKey
): Promise<EncryptedPayload>

class CipherVault implements Cipher {
  readonly isUnlocked: ObservableValue<boolean>
  unlock(key: CryptoKey): void
  lock(): void
  encrypt(data: string | ArrayBuffer): Promise<EncryptedPayload>
  decrypt(payload: EncryptedPayload):  Promise<ArrayBuffer>
}

interface Cipher {
  encrypt(data: string | ArrayBuffer): Promise<EncryptedPayload>
  decrypt(payload: EncryptedPayload):  Promise<ArrayBuffer>
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
type EncryptedPayload = {
  ciphertext: string   // base64 — AES-256-GCM ciphertext
  iv        : string   // base64 — 96-bit IV (never reused)
  salt     ?: string   // base64 — PBKDF2 salt (attached by caller)
  version   : number   // format version
}

type CredentialInfo = {
  id         : string  // credential ID (base64url)
  userName   : string
  displayName: string
  createdAt  : number  // Unix timestamp
}
```

## Security notes

- **PBKDF2 iterations:** 600 000 (OWASP 2024 recommendation). Higher than most legacy implementations.
- **Keys are non-extractable:** `deriveKey()` sets `extractable: false` — keys cannot leave SubtleCrypto.
- **IV is never reused:** `encrypt()` always generates a fresh IV via `crypto.getRandomValues()`.
- **PRF salt is fixed per application:** the same eval salt ensures deterministic key derivation across sessions.
- **Broadcasts / shared secrets:** this library handles single-recipient encryption. For group or broadcast scenarios, symmetric key distribution is the caller's responsibility.

## License

MIT
