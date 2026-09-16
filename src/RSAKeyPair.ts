import { ObservableValue } from "@efficimo/observable";
import { vaultKeys } from "./_internals.ts";
import { AESVault } from "./AESVault.ts";
import type { Cipher, WrappedPrivateKey } from "./types.ts";
import { fromBase64, toBase64 } from "./utils.ts";

const IV_LENGTH = 12;
const SALT_LENGTH = 16;
const PBKDF2_ITERATIONS = 600_000;

async function deriveWrapKey(password: string, salt: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["wrapKey", "unwrapKey"],
  );
}

export class RSAKeyPair implements Cipher<string, string> {
  #privateKey: CryptoKey | null = null;
  #publicCryptoKey: CryptoKey;
  readonly publicKey: JsonWebKey;
  readonly hasPrivateKey: ObservableValue<boolean>;

  private constructor(
    publicCryptoKey: CryptoKey,
    publicKeyJwk: JsonWebKey,
    privateKey?: CryptoKey,
  ) {
    this.#publicCryptoKey = publicCryptoKey;
    this.publicKey = publicKeyJwk;
    this.#privateKey = privateKey ?? null;
    this.hasPrivateKey = new ObservableValue(privateKey !== undefined);
  }

  static async generate(): Promise<RSAKeyPair> {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
    );
    const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    return new RSAKeyPair(keyPair.publicKey, publicKeyJwk, keyPair.privateKey);
  }

  static async fromPublicKey(jwk: JsonWebKey): Promise<RSAKeyPair> {
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["encrypt", "wrapKey"],
    );
    return new RSAKeyPair(publicKey, jwk);
  }

  #requirePrivate(): CryptoKey {
    if (!this.#privateKey) throw new Error("RSAKeyPair: clé privée non disponible");
    return this.#privateKey;
  }

  // -- Cipher<string, string> : chiffrement direct (données ≤ 190 octets) --

  async encrypt(data: string): Promise<string> {
    const encrypted = await crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      this.#publicCryptoKey,
      new TextEncoder().encode(data),
    );
    return toBase64(encrypted);
  }

  async decrypt(base64: string): Promise<string> {
    const decrypted = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      this.#requirePrivate(),
      fromBase64(base64),
    );
    return new TextDecoder().decode(decrypted);
  }

  // -- Enveloppage de clé AES via RSA-OAEP --

  async wrapKey(vault: AESVault): Promise<string> {
    const key = vaultKeys.get(vault);
    if (!key) throw new Error("AESVault is locked");
    return toBase64(
      await crypto.subtle.wrapKey("raw", key, this.#publicCryptoKey, { name: "RSA-OAEP" }),
    );
  }

  async unwrapKey(wrapped: string): Promise<AESVault> {
    const key = await crypto.subtle.unwrapKey(
      "raw",
      fromBase64(wrapped) as Uint8Array<ArrayBuffer>,
      this.#requirePrivate(),
      { name: "RSA-OAEP" },
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"],
    );
    return AESVault.fromKey(key);
  }

  // -- Gestion de la clé privée --

  async lockPrivateKey(password: string): Promise<WrappedPrivateKey> {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const wrapKey = await deriveWrapKey(password, salt);
    const wrapped = await crypto.subtle.wrapKey("pkcs8", this.#requirePrivate(), wrapKey, {
      name: "AES-GCM",
      iv,
    });
    return { salt: toBase64(salt), iv: toBase64(iv), wrappedKey: toBase64(wrapped) };
  }

  async unlockPrivateKey(
    params: WrappedPrivateKey,
    password: string,
    extractable = false,
  ): Promise<void> {
    const wrapKey = await deriveWrapKey(password, fromBase64(params.salt));
    this.#privateKey = await crypto.subtle.unwrapKey(
      "pkcs8",
      fromBase64(params.wrappedKey),
      wrapKey,
      { name: "AES-GCM", iv: fromBase64(params.iv) as Uint8Array<ArrayBuffer> },
      { name: "RSA-OAEP", hash: "SHA-256" },
      extractable,
      ["decrypt", "unwrapKey"],
    );
    this.hasPrivateKey.next(true);
  }
}
