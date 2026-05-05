// WeakMap partagé entre AESVault et RSAKeyPair pour accéder au CryptoKey
// sans l'exposer dans l'API publique
export const vaultKeys = new WeakMap<object, CryptoKey>();
