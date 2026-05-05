import { webcrypto } from "node:crypto";

// jsdom ne fournit pas SubtleCrypto — polyfill avec Node.js webcrypto
Object.defineProperty(globalThis, "crypto", {
  value: webcrypto,
  writable: true,
  configurable: true,
});
