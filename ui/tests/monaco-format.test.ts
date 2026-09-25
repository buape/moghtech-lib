import { test } from "node:test";
import assert from "node:assert/strict";
import {
  formatDocumentAction,
  isFormatLanguage,
  type Format,
} from "../src/components/monaco/format-action.ts";

// Monaco's own pieces which load without a browser.
const { EditorOption } =
  await import("monaco-editor/editor/common/standalone/standaloneEnums.js");
const { ContextKeyExpr } =
  await import("monaco-editor/platform/contextkey/common/contextkey.js");
const { EditorContextKeys } =
  await import("monaco-editor/editor/common/editorContextKeys.js");

const READ_ONLY = EditorOption.readOnly;

/** An editor showing `value`, as much of one as the action uses. */
function fakeEditor(value: string, state: { readOnly: boolean }) {
  const model = {
    isDisposed: () => false,
    getOffsetAt: () => 0,
    getPositionAt: (offset: number) => ({ lineNumber: 1, column: offset + 1 }),
  };
  const editor = {
    value,
    getOption(option: number) {
      assert.equal(option, READ_ONLY);
      return state.readOnly;
    },
    getModel: () => model,
    getPosition: () => ({ lineNumber: 1, column: 1 }),
    getValue: () => editor.value,
    // Like monaco's, it doesn't check `readOnly`.
    setValue(value: string) {
      editor.value = value;
    },
    setPosition() {},
  };
  return editor;
}

function action(format: Format) {
  return formatDocumentAction({
    language: "yaml",
    keybindings: [1],
    readOnlyOption: READ_ONLY as never,
    format,
  });
}

const formatted: Format = async (_, source) => ({
  formatted: `${source.trim()}\n`,
  cursorOffset: 0,
});

test("the format action rewrites a writable editor", async () => {
  const editor = fakeEditor("a: 1   \n\n", { readOnly: false });
  await action(formatted).run(editor as never);
  assert.equal(editor.value, "a: 1\n");
});

test("the format action is off in a read only editor", async () => {
  const format = action(formatted);
  // Monaco checks the precondition (the keybinding's too) against the
  // editor's context keys, kept up to date when `readOnly` changes.
  const precondition = ContextKeyExpr.deserialize(format.precondition);
  const editorKeys = (readOnly: boolean) => ({
    getValue: (key: string) =>
      key === EditorContextKeys.readOnly.key ? readOnly : undefined,
  });
  assert.equal(precondition.evaluate(editorKeys(true)), false);
  assert.equal(precondition.evaluate(editorKeys(false)), true);
  assert.deepEqual(format.keybindings, [1]);

  // Run anyway (eg. `editor.trigger`): the text stays.
  let formats = 0;
  const editor = fakeEditor("a: 1   \n\n", { readOnly: true });
  await action(async (...args) => {
    formats++;
    return formatted(...args);
  }).run(editor as never);
  assert.equal(editor.value, "a: 1   \n\n");
  assert.equal(formats, 0);
});

test("a format finishing after the editor turned read only is dropped", async () => {
  const state = { readOnly: false };
  const editor = fakeEditor("a: 1   \n\n", state);
  await action(async (...args) => {
    // Eg. permissions loaded while prettier was loading
    state.readOnly = true;
    return formatted(...args);
  }).run(editor as never);
  assert.equal(editor.value, "a: 1   \n\n");
});

test("only yaml / typescript / javascript are formatted", () => {
  for (const language of ["yaml", "typescript", "javascript"]) {
    assert.equal(isFormatLanguage(language), true);
  }
  for (const language of ["toml", "json", "shell", undefined]) {
    assert.equal(isFormatLanguage(language), false);
  }
});
