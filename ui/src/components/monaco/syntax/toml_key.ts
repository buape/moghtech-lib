/**
 * The key of a TOML `key = value` entry (bare, quoted or dotted keys)
 * and its `=`, as the groups (key, "="). Shared by the `toml` and
 * `fancy_toml` tokenizers.
 *
 * Monarch requires the groups of a rule to cover the whole match, so
 * the whitespace around the key (indentation, `key = `) is part of the
 * key group. Otherwise the rule throws and the line loses its tokens.
 *
 * Key segments must be joined by a dot, so a run of word characters can
 * only be read one way. The previous `(?:segment\s*\.?\s*)+` could split
 * it into segments every possible way, which it tried on any line
 * without `=`: the time doubled with each character (seconds for a 30
 * character bare word), freezing the tab.
 */
export const TOML_KEY_VALUE_REGEX =
  /(\s*(?:[A-Za-z0-9_+\-]+|"[^"]*"|'[^']*')(?:\s*\.\s*(?:[A-Za-z0-9_+\-]+|"[^"]*"|'[^']*'))*\s*)(=)/;
