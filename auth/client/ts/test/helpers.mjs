// Shared test helpers. Run the tests with `npm test`.

/** An in-memory `Storage`, shared by the stores of one "browser". */
export class MemoryStorage {
  items = new Map();
  getItem(key) {
    return this.items.has(key) ? this.items.get(key) : null;
  }
  setItem(key, value) {
    this.items.set(key, String(value));
  }
  removeItem(key) {
    this.items.delete(key);
  }
  clear() {
    this.items.clear();
  }
}

/** Replace the `localStorage` global (a getter in node 25+). */
export function setLocalStorage(descriptor) {
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    ...descriptor,
  });
}

/** An unsigned JWT for `sub`, enough for `extractUserIdFromJwt`. */
export function jwtFor(sub) {
  const payload = Buffer.from(JSON.stringify({ sub })).toString(
    "base64url",
  );
  return `e30.${payload}.sig`;
}

/** The `storage` event the browser fires in the other tabs. */
export function storageEvent(key) {
  return Object.assign(new Event("storage"), { key });
}
