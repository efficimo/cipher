import { ObservableValue } from "@efficimo/observable";
import { vaultKeys } from "./_internals";
import type { Cipher } from "./types";
import { fromBase64, toBase64 } from "./utils";

const IV_LENGTH = 12;

export class AESVault implements Cipher<string, string> {
  readonly isUnlocked: ObservableValue<boolean>;

  constructor(key: CryptoKey) {
    vaultKeys.set(this, key);
    this.isUnlocked = new ObservableValue(true);
  }

  static async generate(extractable = true): Promise<AESVault> {
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, extractable, [
      "encrypt",
      "decrypt",
    ]);
    return new AESVault(key);
  }

  static async import(base64: string, extractable = true): Promise<AESVault> {
    const key = await crypto.subtle.importKey(
      "raw",
      fromBase64(base64),
      { name: "AES-GCM", length: 256 },
      extractable,
      ["encrypt", "decrypt"],
    );
    return new AESVault(key);
  }

  static fromKey(key: CryptoKey): AESVault {
    return new AESVault(key);
  }

  lock(): void {
    vaultKeys.delete(this);
    void this.isUnlocked.next(false);
  }

  #require(): CryptoKey {
    const key = vaultKeys.get(this);
    if (!key) throw new Error("AESVault is locked");
    return key;
  }

  async export(): Promise<string> {
    return toBase64(await crypto.subtle.exportKey("raw", this.#require()));
  }

  async encrypt(data: string): Promise<string> {
    const key = this.#require();
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(data)),
    );
    const result = new Uint8Array(IV_LENGTH + ciphertext.byteLength);
    result.set(iv);
    result.set(ciphertext, IV_LENGTH);
    return toBase64(result);
  }

  async decrypt(base64: string): Promise<string> {
    const key = this.#require();
    const data = fromBase64(base64);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: data.slice(0, IV_LENGTH) },
      key,
      data.slice(IV_LENGTH),
    );
    return new TextDecoder().decode(plaintext);
  }
}
