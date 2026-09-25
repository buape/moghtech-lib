import { test } from "node:test";
import assert from "node:assert/strict";
import "./resolve-extensionless.ts";

const { backtoPath, sameOriginPath } = await import("../src/auth/utils.ts");

const ORIGIN = "http://app.example:9230";

function at(search: string) {
  (globalThis as { location?: unknown }).location = {
    origin: ORIGIN,
    search,
  };
}

test("sameOriginPath keeps paths of the app", () => {
  at("");
  assert.equal(sameOriginPath("/"), "/");
  assert.equal(sameOriginPath("/tools"), "/tools");
  assert.equal(sameOriginPath("/tools?tab=a#b"), "/tools?tab=a#b");
  assert.equal(sameOriginPath("/profile?x=a%2Fb"), "/profile?x=a%2Fb");
  // Encoded slashes stay part of the path
  assert.equal(sameOriginPath("/%2F%2Fevil.example"), "/%2F%2Fevil.example");
  assert.equal(sameOriginPath("/%5Cevil.example"), "/%5Cevil.example");
});

test("sameOriginPath refuses anything which leaves the app", () => {
  at("");
  for (const target of [
    null,
    undefined,
    "",
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    " javascript:alert(1)",
    "data:text/html,hi",
    "//evil.example",
    "/\\evil.example",
    "\\\\evil.example",
    "\\/evil.example",
    // Tabs and newlines are removed when the url is parsed
    "/\t/evil.example",
    "/\n/evil.example",
    "https://evil.example",
    `${ORIGIN}@evil.example/login`,
    "@evil.example",
    "evil.example",
    // Absolute, even to this app: only relative paths are expected
    `${ORIGIN}/tools`,
  ]) {
    assert.equal(sameOriginPath(target), "/", JSON.stringify(target));
    assert.equal(
      sameOriginPath(target, "/home"),
      "/home",
      JSON.stringify(target),
    );
  }
});

test("sameOriginPath doesn't return a protocol relative path", () => {
  at("");
  // Dot segments resolve to a path starting with `//`
  assert.equal(sameOriginPath("/.//evil.example"), "/evil.example");
  assert.equal(sameOriginPath("/%2e//evil.example"), "/evil.example");
  assert.equal(sameOriginPath("/..//evil.example/x"), "/evil.example/x");
  assert.equal(sameOriginPath("/./\\evil.example"), "/evil.example");
});

test("backtoPath reads the backto query param", () => {
  at("?backto=%2Ftools%3Ftab%3Da");
  assert.equal(backtoPath(), "/tools?tab=a");
  at("?backto=javascript%3Aalert(1)");
  assert.equal(backtoPath(), "/");
  at("?backto=%2F%2Fevil.example");
  assert.equal(backtoPath(), "/");
  at("?backto=https%3A%2F%2Fevil.example");
  assert.equal(backtoPath("/home"), "/home");
  at("");
  assert.equal(backtoPath(), "/");
});

test("backtoPath drops what an external login returns with", () => {
  // The provider sends the tab back to `backto`, with the server's
  // params added after the query already there.
  const planted =
    "/?login_error=Your%20account%20is%20locked.%20Call%20%2B1-555-0100" +
    "&redeem_ready=0";
  at(`?backto=${encodeURIComponent(planted)}`);
  assert.equal(backtoPath(), "/");
  for (const param of [
    "redeem_ready=0",
    "totp=true",
    "passkey=e30",
    "login_error=spoofed",
    "link_error=spoofed",
    // Read the same once decoded
    "login%5Ferror=spoofed",
    "redeem%5Fready=0",
  ]) {
    at(`?backto=${encodeURIComponent(`/tools?tab=a&${param}&b=c#h`)}`);
    assert.equal(backtoPath(), "/tools?tab=a&b=c#h", param);
    at(`?backto=${encodeURIComponent(`/tools?${param}`)}`);
    assert.equal(backtoPath(), "/tools", param);
  }
  // The rest of the query stays as it is.
  at(`?backto=${encodeURIComponent("/tools?q=a%20b+c&totp=true&x=%2F")}`);
  assert.equal(backtoPath(), "/tools?q=a%20b+c&x=%2F");
  // Only names, not values, and not the fragment (which isn't read).
  at(`?backto=${encodeURIComponent("/n?note=login_error#login_error=x")}`);
  assert.equal(backtoPath(), "/n?note=login_error#login_error=x");
  at(`?backto=${encodeURIComponent("/n?x=%26login_error%3Dy")}`);
  assert.equal(backtoPath(), "/n?x=%26login_error%3Dy");
});
