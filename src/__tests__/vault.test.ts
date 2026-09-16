import { describe, expect, it } from "vitest";
import { AESVault } from "../AESVault.ts";
import { FileCipher } from "../FileCipher.ts";
import { RSAKeyPair } from "../RSAKeyPair.ts";

describe("AESVault", () => {
  it("generate produit un vault déverrouillé", async () => {
    const vault = await AESVault.generate();
    expect(vault.isUnlocked.getValue()).toBe(true);
  });

  it("lock désactive le vault", async () => {
    const vault = await AESVault.generate();
    vault.lock();
    expect(vault.isUnlocked.getValue()).toBe(false);
    await expect(vault.encrypt("secret")).rejects.toThrow("locked");
  });

  it("encrypt / decrypt round-trip", async () => {
    const vault = await AESVault.generate();
    const blob = await vault.encrypt("hello world");
    expect(await vault.decrypt(blob)).toBe("hello world");
  });

  it("export / import round-trip", async () => {
    const vault = await AESVault.generate();
    const blob = await vault.encrypt("data");
    const exported = await vault.export();
    const vault2 = await AESVault.import(exported);
    expect(await vault2.decrypt(blob)).toBe("data");
  });

  it("isUnlocked émet les changements d'état", async () => {
    const vault = await AESVault.generate();
    const states: boolean[] = [];
    vault.isUnlocked.subscribe((v: boolean) => states.push(v));
    vault.lock();
    expect(states).toContain(false);
  });
});

describe("RSAKeyPair", () => {
  it("generate produit une paire avec clé privée", async () => {
    const pair = await RSAKeyPair.generate();
    expect(pair.hasPrivateKey.getValue()).toBe(true);
  });

  it("fromPublicKey n'a pas de clé privée", async () => {
    const pair = await RSAKeyPair.generate();
    const publicOnly = await RSAKeyPair.fromPublicKey(pair.publicKey);
    expect(publicOnly.hasPrivateKey.getValue()).toBe(false);
  });

  it("encrypt / decrypt round-trip (données courtes)", async () => {
    const pair = await RSAKeyPair.generate();
    const blob = await pair.encrypt("token-secret");
    expect(await pair.decrypt(blob)).toBe("token-secret");
  });

  it("wrapKey / unwrapKey préserve le contenu du vault", async () => {
    const pair = await RSAKeyPair.generate();
    const vault = await AESVault.generate();
    const plaintext = "données sensibles";
    const encrypted = await vault.encrypt(plaintext);
    const wrapped = await pair.wrapKey(vault);
    const restored = await pair.unwrapKey(wrapped);
    expect(await restored.decrypt(encrypted)).toBe(plaintext);
  });

  it("lockPrivateKey / unlockPrivateKey round-trip", async () => {
    const pair = await RSAKeyPair.generate();
    const vault = await AESVault.generate();
    const encrypted = await vault.encrypt("secret");
    const wrapped = await pair.wrapKey(vault);
    const lockedKey = await pair.lockPrivateKey("mot-de-passe");
    const pair2 = await RSAKeyPair.fromPublicKey(pair.publicKey);
    await pair2.unlockPrivateKey(lockedKey, "mot-de-passe");
    const restored = await pair2.unwrapKey(wrapped);
    expect(await restored.decrypt(encrypted)).toBe("secret");
  });
});

describe("FileCipher", () => {
  it("délègue au cipher sous-jacent", async () => {
    const vault = await AESVault.generate();
    const file = FileCipher.from(vault);
    const blob = await file.encrypt('{"key":"value"}');
    expect(await file.decrypt(blob)).toBe('{"key":"value"}');
  });

  it("accepte n'importe quel Cipher compatible", async () => {
    const pair = await RSAKeyPair.generate();
    const file = FileCipher.from(pair);
    const blob = await file.encrypt("court texte");
    expect(await file.decrypt(blob)).toBe("court texte");
  });
});
