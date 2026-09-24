import assert from "node:assert/strict";
import { beforeEach, it, mock } from "node:test";
import { setLocalStorage } from "./helpers.mjs";

// Browsers blocking site data throw on reading `localStorage`.
setLocalStorage({
  get: () => {
    throw new DOMException("The operation is insecure.", "SecurityError");
  },
});

// Expected: "localStorage is unavailable" warnings.
beforeEach(() => mock.method(console, "warn", () => {}));

it("importing the package works with storage blocked", async () => {
  const MoghAuth = await import("../dist/lib.js");
  assert.equal(MoghAuth.LOGIN_TOKENS, undefined);
  assert.equal(MoghAuth.createLoginTokens(), undefined);
  assert.equal(typeof MoghAuth.MoghAuthClient, "function");
});

it("storage which throws on use is unavailable", async () => {
  const { createLoginTokens } = await import("../dist/tokens.js");
  setLocalStorage({
    value: {
      getItem() {
        throw new DOMException("denied", "SecurityError");
      },
    },
  });
  assert.equal(createLoginTokens(), undefined);
});
