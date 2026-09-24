import { test } from "node:test";
import assert from "node:assert/strict";
import { backtoPath, sameOriginPath } from "../src/auth/utils.ts";

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
