import type { Cipher } from "./types.ts";

export class FileCipher implements Cipher<string, string> {
  #cipher: Cipher<string, string>;

  private constructor(cipher: Cipher<string, string>) {
    this.#cipher = cipher;
  }

  static from(cipher: Cipher<string, string>): FileCipher {
    return new FileCipher(cipher);
  }

  encrypt(content: string): Promise<string> {
    return this.#cipher.encrypt(content);
  }

  decrypt(blob: string): Promise<string> {
    return this.#cipher.decrypt(blob);
  }
}
