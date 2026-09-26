// The Prettier format action of `MonacoEditor`. Internal (not
// re-exported). Only type imports: the unit tests load it in Node, where
// the monaco-editor entry can't load (it needs a browser).
import type { editor } from "monaco-editor";

export type FormatLanguage = "yaml" | "typescript" | "javascript";

export function isFormatLanguage(
  language: string | undefined,
): language is FormatLanguage {
  return (
    language === "yaml" ||
    language === "typescript" ||
    language === "javascript"
  );
}

/** Formats `source`, and moves the cursor offset along. */
export type Format = (
  language: FormatLanguage,
  source: string,
  cursorOffset: number,
) => Promise<{ formatted: string; cursorOffset: number }>;

/**
 * Monaco's context key of a writable editor (`EditorContextKeys.readOnly`
 * negated). Monaco keeps it up to date when the `readOnly` option
 * changes.
 */
const WRITABLE_EDITOR = "!editorReadonly";

const FORMAT_ACTION_ID = "mogh.format-document";

/**
 * The "Format Document (Prettier)" action of an editor showing
 * `language`, for `editor.addAction`.
 *
 * The formatted text replaces the model's content as one edit
 * (`executeEdits`), which undo reverts, leaving the earlier undo history
 * as it was (`setValue` would clear it). Formatting can take a while (the
 * first time Prettier and its plugins are loaded), and the editor stays
 * editable meanwhile: a result for text which has changed since is
 * dropped, rather than overwriting what was typed.
 *
 * Only for a writable editor. The action is off (its keybinding too)
 * while the editor is read only, also when `readOnly` changes later, and
 * a format which finishes after the editor turned read only is dropped.
 */
export function formatDocumentAction({
  language,
  keybindings,
  readOnlyOption,
  format,
}: {
  language: FormatLanguage;
  keybindings: number[];
  /** `monaco.editor.EditorOption.readOnly` */
  readOnlyOption: editor.EditorOption.readOnly;
  format: Format;
}): editor.IActionDescriptor {
  return {
    id: FORMAT_ACTION_ID,
    label: "Format Document (Prettier)",
    keybindings,
    precondition: WRITABLE_EDITOR,
    run: async (codeEditor) => {
      const readOnly = () => codeEditor.getOption(readOnlyOption);
      if (readOnly()) return;
      const model = codeEditor.getModel();
      if (!model) return;
      // Any edit (typing, undo) changes the version.
      const version = model.getVersionId();
      const source = codeEditor.getValue();
      const position = codeEditor.getPosition();
      const beforeOffset = (position && model.getOffsetAt(position)) ?? 0;
      const { formatted, cursorOffset } = await format(
        language,
        source,
        beforeOffset,
      );
      // Disposed / switched model, edited or turned read only while
      // formatting.
      if (
        model.isDisposed() ||
        codeEditor.getModel() !== model ||
        model.getVersionId() !== version ||
        readOnly()
      ) {
        return;
      }
      // Already formatted: no edit to undo.
      if (formatted === source) return;
      // Undo stops keep the format one undo step of its own.
      codeEditor.pushUndoStop();
      const applied = codeEditor.executeEdits(FORMAT_ACTION_ID, [
        { range: model.getFullModelRange(), text: formatted },
      ]);
      codeEditor.pushUndoStop();
      if (applied) {
        codeEditor.setPosition(model.getPositionAt(cursorOffset));
      }
    },
  };
}
