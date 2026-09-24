import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { it } from "node:test";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

it("relative imports in dist have a .js extension", () => {
  // Required by node16 / nodenext module resolution.
  const dist = path.join(root, "dist");
  for (const file of readdirSync(dist)) {
    const contents = readFileSync(path.join(dist, file), "utf8");
    for (const [, specifier] of contents.matchAll(
      /(?:from|import)\s*\(?\s*"(\.{1,2}\/[^"]*)"/g,
    )) {
      assert.ok(
        specifier.endsWith(".js"),
        `${file} imports "${specifier}" without the .js extension`,
      );
    }
  }
});

it("generate_types fails when typeshare fails", () => {
  const types = path.join(root, "src/types.ts");
  const before = readFileSync(types, "utf8");
  // Run from the package directory, without typeshare on the PATH.
  const result = spawnSync(
    process.execPath,
    [path.join(root, "generate_types.mjs")],
    { cwd: root, env: { ...process.env, PATH: "" }, encoding: "utf8" },
  );
  assert.notEqual(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stderr, /failed to generate types/);
  assert.equal(readFileSync(types, "utf8"), before);
});
