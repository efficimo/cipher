import { beforeEach, describe, expect, it, vi } from "vitest";
import { BiometricAuth, isBiometricSupported } from "../webauthn";

const fakeRawId = crypto.getRandomValues(new Uint8Array(16)).buffer as ArrayBuffer;
// Buffer.alloc is native Node.js — avoids jsdom realm instanceof mismatch with webcrypto
const fakePrfOutput = Buffer.alloc(32);

function makeMockCredential(rawId: ArrayBuffer) {
  return {
    rawId,
    getClientExtensionResults: () => ({
      prf: { results: { first: fakePrfOutput } },
    }),
  };
}

describe("isBiometricSupported", () => {
  it("returns false when PublicKeyCredential is unavailable", async () => {
    const original = globalThis.PublicKeyCredential;
    // @ts-expect-error
    globalThis.PublicKeyCredential = undefined;
    expect(await isBiometricSupported()).toBe(false);
    globalThis.PublicKeyCredential = original;
  });

  it("returns true when capabilities include prf", async () => {
    const original = globalThis.PublicKeyCredential;
    globalThis.PublicKeyCredential = {
      getClientCapabilities: async () => ({ prf: true }),
    } as unknown as typeof PublicKeyCredential;
    expect(await isBiometricSupported()).toBe(true);
    globalThis.PublicKeyCredential = original;
  });

  it("returns false when prf is absent from capabilities", async () => {
    const original = globalThis.PublicKeyCredential;
    globalThis.PublicKeyCredential = {
      getClientCapabilities: async () => ({ uv: true }),
    } as unknown as typeof PublicKeyCredential;
    expect(await isBiometricSupported()).toBe(false);
    globalThis.PublicKeyCredential = original;
  });
});

describe("BiometricAuth", () => {
  let auth: BiometricAuth;

  beforeEach(() => {
    auth = new BiometricAuth();
    localStorage.clear();
    Object.defineProperty(globalThis.navigator, "credentials", {
      value: { create: vi.fn(), get: vi.fn() },
      configurable: true,
      writable: true,
    });
  });

  describe("register", () => {
    it("returns CredentialInfo with correct fields", async () => {
      vi.spyOn(navigator.credentials, "create").mockResolvedValue(
        makeMockCredential(fakeRawId) as unknown as PublicKeyCredential,
      );
      const info = await auth.register({ userId: "u1", userName: "alice" });
      expect(info.userName).toBe("alice");
      expect(info.displayName).toBe("alice");
      expect(typeof info.id).toBe("string");
      expect(info.createdAt).toBeGreaterThan(0);
    });

    it("stores credential in localStorage", async () => {
      vi.spyOn(navigator.credentials, "create").mockResolvedValue(
        makeMockCredential(fakeRawId) as unknown as PublicKeyCredential,
      );
      await auth.register({ userId: "u1", userName: "alice", displayName: "Alice" });
      expect(auth.listCredentials()).toHaveLength(1);
    });

    it("throws when creation is cancelled", async () => {
      vi.spyOn(navigator.credentials, "create").mockResolvedValue(null);
      await expect(auth.register({ userId: "u1", userName: "alice" })).rejects.toThrow("cancelled");
    });
  });

  describe("authenticate", () => {
    it("returns a non-extractable AES-256-GCM CryptoKey", async () => {
      vi.spyOn(navigator.credentials, "get").mockResolvedValue(
        makeMockCredential(fakeRawId) as unknown as PublicKeyCredential,
      );
      const key = await auth.authenticate("dGVzdA");
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.extractable).toBe(false);
      expect(key.algorithm.name).toBe("AES-GCM");
    });

    it("throws when PRF output is absent", async () => {
      vi.spyOn(navigator.credentials, "get").mockResolvedValue({
        rawId: fakeRawId,
        getClientExtensionResults: () => ({}),
      } as unknown as PublicKeyCredential);
      await expect(auth.authenticate("dGVzdA")).rejects.toThrow("PRF");
    });

    it("throws when authentication is cancelled", async () => {
      vi.spyOn(navigator.credentials, "get").mockResolvedValue(null);
      await expect(auth.authenticate("dGVzdA")).rejects.toThrow("cancelled");
    });
  });

  describe("listCredentials / removeCredential", () => {
    it("returns empty array initially", () => {
      expect(auth.listCredentials()).toEqual([]);
    });

    it("removeCredential filters out the target credential", async () => {
      vi.spyOn(navigator.credentials, "create").mockResolvedValue(
        makeMockCredential(fakeRawId) as unknown as PublicKeyCredential,
      );
      const info = await auth.register({ userId: "u1", userName: "alice" });
      auth.removeCredential(info.id);
      expect(auth.listCredentials()).toHaveLength(0);
    });
  });
});
