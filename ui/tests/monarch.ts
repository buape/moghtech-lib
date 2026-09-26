import { registerHooks } from "node:module";

// Runs the real syntax definitions through Monaco's own Monarch
// compiler and tokenizer. The "monaco-editor" entry needs a browser
// (css, workers), so the syntax files get a stub which only records the
// registered tokenizers. The syntax files' extensionless relative
// imports resolve to their .ts files, like the bundler does.
//
// Import this first, then load the syntax files with `loadSyntax`:
// static imports are all resolved before any module runs.
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

const SYNTAX = new URL("../src/components/monaco/syntax/", import.meta.url);

/** Loads (registers) syntax files, eg. `loadSyntax("toml")`. */
export async function loadSyntax(...names: string[]) {
  for (const name of names) {
    await import(new URL(`${name}.ts`, SYNTAX).href);
  }
}

const { compile } = await import(
  // @ts-ignore: monaco-editor ships no types for its internals
  "monaco-editor/editor/standalone/common/monarch/monarchCompile.js"
);
const { MonarchTokenizer } = await import(
  // @ts-ignore: monaco-editor ships no types for its internals
  "monaco-editor/editor/standalone/common/monarch/monarchLexer.js"
);

export type Token = { offset: number; type: string };

/**
 * A tokenizer of a loaded language, fed one line after the other (the
 * state carries over, eg. inside a multi line string). Throws where
 * Monaco would drop the line's tokens.
 */
export function tokenizer(language: string) {
  const lexer = compile(language, monarch[language]);
  const languageService = {
    languageIdCodec: { encodeLanguageId: () => 1 },
    isRegisteredLanguageId: () => false,
    getLanguageIdByLanguageName: () => null,
  };
  const themeService = {
    getColorTheme: () => ({ tokenTheme: { match: () => 0 } }),
  };
  // `editor.maxTokenizationLineLength`: longer lines aren't tokenized.
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
  return (line: string): Token[] => {
    const result = tokenizer.tokenize(line, true, state);
    state = result.endState;
    return result.tokens;
  };
}

/** The type of the token covering the character at `offset`. */
export function tokenAt(tokens: Token[], offset: number) {
  let type: string | undefined;
  for (const token of tokens) {
    if (token.offset > offset) break;
    type = token.type;
  }
  return type;
}
