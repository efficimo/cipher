import type { CredentialInfo } from "./types";

const STORAGE_KEY = "@efficimo/cipher:credentials";

// Fixed PRF eval salt — same salt + same biometric = same key (deterministic)
const PRF_EVAL_SALT = new TextEncoder().encode("@efficimo/cipher:prf:v1");

interface PRFExtensionResults {
  prf?: { results?: { first?: ArrayBuffer } };
}

export async function isBiometricSupported(): Promise<boolean> {
  if (typeof globalThis.PublicKeyCredential === "undefined") return false;
  try {
    const ctor = PublicKeyCredential as unknown as {
      getClientCapabilities?: () => Promise<Record<string, unknown>>;
    };
    const capabilities = await ctor.getClientCapabilities?.();
    return capabilities != null && "prf" in capabilities;
  } catch {
    return false;
  }
}

export class BiometricAuth {
  async register(options: {
    userId: string;
    userName: string;
    displayName?: string;
    rpName?: string;
  }): Promise<CredentialInfo> {
    const { userId, userName, displayName = userName, rpName = "efficimo" } = options;

    const credential = (await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: rpName },
        user: {
          id: new TextEncoder().encode(userId),
          name: userName,
          displayName,
        },
        pubKeyCredParams: [{ alg: -7, type: "public-key" }],
        authenticatorSelection: {
          userVerification: "required",
          residentKey: "preferred",
        },
        extensions: {
          prf: { eval: { first: PRF_EVAL_SALT } },
        } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential | null;

    if (!credential) throw new Error("Credential creation cancelled");

    const info: CredentialInfo = {
      id: toBase64url(credential.rawId),
      userName,
      displayName,
      createdAt: Date.now(),
    };

    const existing = this.listCredentials();
    localStorage.setItem(STORAGE_KEY, JSON.stringify([...existing, info]));

    return info;
  }

  async authenticate(credentialId: string): Promise<CryptoKey> {
    const assertion = (await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ id: fromBase64url(credentialId), type: "public-key" }],
        userVerification: "required",
        extensions: {
          prf: { eval: { first: PRF_EVAL_SALT } },
        } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential | null;

    if (!assertion) throw new Error("Authentication cancelled");

    const ext = assertion.getClientExtensionResults() as PRFExtensionResults;
    const prfOutput = ext.prf?.results?.first;

    if (!prfOutput) throw new Error("PRF extension not supported by this authenticator");

    return crypto.subtle.importKey("raw", prfOutput, { name: "AES-GCM", length: 256 }, false, [
      "encrypt",
      "decrypt",
    ]);
  }

  listCredentials(): CredentialInfo[] {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? (JSON.parse(raw) as CredentialInfo[]) : [];
    } catch {
      return [];
    }
  }

  removeCredential(credentialId: string): void {
    const filtered = this.listCredentials().filter((c) => c.id !== credentialId);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(filtered));
  }
}

function toBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function fromBase64url(b64url: string): Uint8Array<ArrayBuffer> {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
