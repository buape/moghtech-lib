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

/**
 * The "Format Document (Prettier)" action of an editor showing
 * `language`, for `editor.addAction`.
 *
 * Only for a writable editor: `setValue` doesn't check `readOnly`, and
 * would rewrite what a read only editor shows (and call its
 * `onChange`). The action is off (its keybinding too) while the editor
 * is read only, also when `readOnly` changes later, and a format which
 * finishes after the editor turned read only is dropped.
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
    id: "mogh.format-document",
    label: "Format Document (Prettier)",
    keybindings,
    precondition: WRITABLE_EDITOR,
    run: async (codeEditor) => {
      const readOnly = () => codeEditor.getOption(readOnlyOption);
      if (readOnly()) return;
      const model = codeEditor.getModel();
      if (!model) return;
      const position = codeEditor.getPosition();
      const beforeOffset = (position && model.getOffsetAt(position)) ?? 0;
      const { formatted, cursorOffset } = await format(
        language,
        codeEditor.getValue(),
        beforeOffset,
      );
      // Disposed / switched model, or turned read only, while formatting.
      if (model.isDisposed() || codeEditor.getModel() !== model || readOnly()) {
        return;
      }
      codeEditor.setValue(formatted);
      codeEditor.setPosition(model.getPositionAt(cursorOffset));
    },
  };
}
