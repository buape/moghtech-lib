import { test } from "node:test";
import assert from "node:assert/strict";
import { deepCompare } from "../src/utils.ts";

test("deepCompare compares keys, not only values", () => {
  // A key missing on one side is not the same as an undefined value.
  assert.equal(deepCompare({ a: undefined, b: 1 }, { b: 1, c: 2 }), false);
  assert.equal(deepCompare({ a: undefined }, { b: undefined }), false);
  assert.equal(deepCompare({ b: 1, c: 2 }, { a: undefined, b: 1 }), false);
  assert.equal(
    deepCompare({ x: { a: undefined } }, { x: { b: undefined } }),
    false,
  );
});

test("deepCompare tells arrays from objects", () => {
  assert.equal(deepCompare([1], { 0: 1 }), false);
  assert.equal(deepCompare({ 0: 1 }, [1]), false);
});

test("deepCompare equal values", () => {
  assert.equal(deepCompare({ a: 1, b: 2 }, { b: 2, a: 1 }), true);
  assert.equal(deepCompare({ a: undefined }, { a: undefined }), true);
  assert.equal(deepCompare([1, { a: [2] }], [1, { a: [2] }]), true);
  assert.equal(deepCompare([1, 2], [2, 1]), false);
  assert.equal(deepCompare(null, null), true);
  assert.equal(deepCompare(null, {}), false);
  assert.equal(deepCompare("a", "a"), true);
  assert.equal(deepCompare(1, "1"), false);
});
