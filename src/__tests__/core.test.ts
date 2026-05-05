import { describe, expect, it } from "vitest";
import { AESVault } from "../AESVault";
import { deriveKey, generateSalt } from "../core";

describe("generateSalt", () => {
  it("returns 16 bytes", () => {
    const salt = generateSalt();
    expect(salt).toBeInstanceOf(Uint8Array);
    expect(salt.byteLength).toBe(16);
  });

  it("produces unique values", () => {
    expect(generateSalt()).not.toEqual(generateSalt());
  });
});

describe("deriveKey", () => {
  it("returns a non-extractable AES-256-GCM CryptoKey", async () => {
    const key = await deriveKey("password", generateSalt());
    expect(key).toBeInstanceOf(CryptoKey);
    expect(key.extractable).toBe(false);
    expect(key.algorithm.name).toBe("AES-GCM");
  });

  it("same password + same salt produces equivalent keys", async () => {
    const salt = generateSalt();
    const k1 = await deriveKey("test", salt);
    const k2 = await deriveKey("test", salt);
    const v1 = AESVault.fromKey(k1);
    const encrypted = await v1.encrypt("hello");
    const v2 = AESVault.fromKey(k2);
    expect(await v2.decrypt(encrypted)).toBe("hello");
  });
});
