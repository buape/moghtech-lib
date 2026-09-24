import { test } from "node:test";
import assert from "node:assert/strict";
import { TOML_KEY_VALUE_REGEX } from "../src/components/monaco/syntax/toml_key.ts";

// Monarch anchors every rule at the current position like this
// (monaco-editor monarchCompile.js), and retries the rules one
// character further along when none matches.
const anchored = new RegExp("^(?:" + TOML_KEY_VALUE_REGEX.source + ")");

/** Runs the rule at every position of the line, as monarch would. */
function tokenizeLine(line: string) {
  for (let pos = 0; pos < line.length; pos++) {
    anchored.exec(line.slice(pos));
  }
}

test("toml key rule is fast on lines without '='", () => {
  const lines = [
    // A key being typed, before its '='. The old rule took ~30s here.
    "pre_deploy_command_for_stack_x",
    // An unquoted token
    "token ghp_" + "a".repeat(40),
    // A long bare word
    "x".repeat(5_000),
    // Words split by spaces / dots
    "a b c d e f g h i j k l m n o p q r s t u v w x y z ".repeat(40),
    "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.".repeat(40),
    " ".repeat(5_000) + "x",
  ];
  for (const line of lines) {
    const start = performance.now();
    tokenizeLine(line);
    const elapsed = performance.now() - start;
    assert.ok(
      elapsed < 1_000,
      `${elapsed.toFixed(0)}ms for a ${line.length} char line`,
    );
  }
});

test("toml key rule matches keys and their '='", () => {
  const cases: [string, string][] = [
    ["key = 1", "key"],
    ["  key = 1", "key"],
    ["\tkey\t=\t1", "key"],
    ["a.b = 1", "a.b"],
    ["a . b = 1", "a . b"],
    ['"x".y.z = 1', '"x".y.z'],
    ["'literal key' = 1", "'literal key'"],
    ['"" = 1', '""'],
    ["bare-key_1+2 = 1", "bare-key_1+2"],
    ["key= 1", "key"],
    ["key=1", "key"],
  ];
  for (const [line, key] of cases) {
    const match = anchored.exec(line);
    assert.ok(match, line);
    // Monarch throws unless the groups cover the whole match
    // ("with groups, all characters should be matched in
    // consecutive groups").
    assert.equal(match[1] + match[2], match[0], line);
    assert.equal(match[1].trim(), key, line);
    assert.equal(match[2], "=", line);
  }
  assert.equal(anchored.exec("key"), null);
  assert.equal(anchored.exec("[table]"), null);
});
