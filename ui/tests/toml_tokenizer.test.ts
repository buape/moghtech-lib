import { test } from "node:test";
import assert from "node:assert/strict";
import { registerHooks } from "node:module";

// Runs the real `toml` / `fancy_toml` definitions through Monaco's own
// Monarch compiler and tokenizer. The "monaco-editor" entry needs a
// browser (css, workers), so the syntax files get a stub which only
// records the registered tokenizers. The syntax files' extensionless
// relative imports resolve to their .ts files, like the bundler does.
const monarch: Record<string, unknown> = {};
(globalThis as { __moghMonarch?: unknown }).__moghMonarch = monarch;
const MONACO_STUB = `
const captured = globalThis.__moghMonarch;
export const languages = {
  register() {},
  setLanguageConfiguration() {},
  setMonarchTokensProvider(id, language) { captured[id] = language; },
};
export const editor = {};
`;
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "monaco-editor") {
      return {
        url: "data:text/javascript," + encodeURIComponent(MONACO_STUB),
        shortCircuit: true,
      };
    }
    if (
      specifier.startsWith(".") &&
      context.parentURL?.endsWith(".ts") &&
      !/\.[cm]?[jt]sx?$/.test(specifier)
    ) {
      return nextResolve(specifier + ".ts", context);
    }
    return nextResolve(specifier, context);
  },
});

await import("../src/components/monaco/syntax/toml.ts");
await import("../src/components/monaco/syntax/fancy_toml.ts");
const { compile } = await import(
  // @ts-ignore: monaco-editor ships no types for its internals
  "monaco-editor/editor/standalone/common/monarch/monarchCompile.js"
);
const { MonarchTokenizer } = await import(
  // @ts-ignore: monaco-editor ships no types for its internals
  "monaco-editor/editor/standalone/common/monarch/monarchLexer.js"
);

type Token = { offset: number; type: string };

function tokenizer(language: string) {
  const lexer = compile(language, monarch[language]);
  const languageService = {
    languageIdCodec: { encodeLanguageId: () => 1 },
    isRegisteredLanguageId: () => false,
    getLanguageIdByLanguageName: () => null,
  };
  const themeService = {
    getColorTheme: () => ({ tokenTheme: { match: () => 0 } }),
  };
  const configurationService = {
    getValue: () => 20_000,
    onDidChangeConfiguration: () => ({ dispose() {} }),
  };
  const tokenizer = new MonarchTokenizer(
    languageService,
    themeService,
    language,
    lexer,
    configurationService,
  );
  let state = tokenizer.getInitialState();
  /** Throws where Monaco would drop the line's tokens. */
  return (line: string): Token[] => {
    const result = tokenizer.tokenize(line, true, state);
    state = result.endState;
    return result.tokens;
  };
}

/** The type of the token covering the character at `offset`. */
function tokenAt(tokens: Token[], offset: number) {
  let type: string | undefined;
  for (const token of tokens) {
    if (token.offset > offset) break;
    type = token.type;
  }
  return type;
}

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
