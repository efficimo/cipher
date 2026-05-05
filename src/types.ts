export interface Cipher<TData = string, TPayload = string> {
  encrypt(data: TData): Promise<TPayload>;
  decrypt(payload: TPayload): Promise<TData>;
}

export interface WrappedPrivateKey {
  salt: string; // base64 — sel PBKDF2
  iv: string; // base64 — vecteur d'initialisation AES-GCM
  wrappedKey: string; // base64 — clé privée PKCS8 enveloppée
}

export interface KeyDerivationOptions {
  iterations?: number; // défaut : 600_000 (OWASP 2024)
  hash?: "SHA-256" | "SHA-512"; // défaut : "SHA-256"
}

export interface CredentialInfo {
  id: string; // credential ID (base64url)
  userName: string;
  displayName: string;
  createdAt: number; // Unix timestamp
}
