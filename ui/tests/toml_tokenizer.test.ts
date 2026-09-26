import { test } from "node:test";
import assert from "node:assert/strict";
import { loadSyntax, tokenAt, tokenizer, type Token } from "./monarch.ts";

// The real `toml` / `fancy_toml` definitions, through Monaco's own
// Monarch compiler and tokenizer (see ./monarch.ts).
await loadSyntax("toml", "fancy_toml");

for (const language of ["toml", "fancy_toml"]) {
  test(`${language} tokenizes keys and table headers`, () => {
    const tokenize = tokenizer(language);
    const lines = [
      "key = 1",
      "key=1",
      'a.b = "x"',
      "  indented = true",
      "\tindented = false",
      'name = "komodo"',
      "x . y = 2",
      "\"quoted key\" = 'literal'",
      "[[resource]]",
      "[resource.config]",
      "  [[indented]]",
      "  [indented.table]",
      "# comment",
      'tags = ["a", "b"]',
      "inline = { a = 1, b = 2 }",
    ];
    for (const line of lines) {
      let tokens: Token[];
      try {
        tokens = tokenize(line);
      } catch (error) {
        assert.fail(`${JSON.stringify(line)}: ${error}`);
      }
      const header = line.trimStart().startsWith("[");
      if (header) {
        const name = line.search(/[^\s[]/);
        assert.match(
          tokenAt(tokens, name) ?? "",
          /^entity\.other\.attribute-name\.table/,
          `table name of ${JSON.stringify(line)}`,
        );
      }
      const eq = line.indexOf("=");
      if (eq > 0 && !header && !line.startsWith("#")) {
        assert.equal(
          tokenAt(tokens, eq),
          "delimiter.toml",
          `'=' of ${JSON.stringify(line)}`,
        );
      }
    }
  });
}
