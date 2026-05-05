import type { KeyDerivationOptions } from "./types";

export function generateSalt(): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(16));
}

export async function deriveKey(
  password: string,
  salt: Uint8Array<ArrayBuffer>,
  options: KeyDerivationOptions = {},
): Promise<CryptoKey> {
  const { iterations = 600_000, hash = "SHA-256" } = options;
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}
