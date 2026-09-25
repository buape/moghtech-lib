import "./init";

import { useEffect, useRef, useState } from "react";
import { DiffEditor, Editor } from "@monaco-editor/react";
import * as monaco from "monaco-editor";
import { useViewportSize } from "@mantine/hooks";
import { Box, useComputedColorScheme } from "@mantine/core";
import {
  MonacoDiffEditorProps,
  MonacoEditorProps,
  MonacoLanguage,
} from "./common";
import {
  formatDocumentAction,
  FormatLanguage,
  isFormatLanguage,
} from "./format-action";

const MIN_EDITOR_HEIGHT = 56;

/** Makes each editor's model path unique, see `modelPath`. */
let editorInstanceCounter = 0;

/** Prettier embeds the full typescript parser - only load it on demand. */
async function formatWithCursor(
  language: FormatLanguage,
  source: string,
  cursorOffset: number,
) {
  if (language === "yaml") {
    const [prettier, pluginYaml] = await Promise.all([
      import("prettier/standalone"),
      import("prettier/plugins/yaml"),
    ]);
    return await prettier.formatWithCursor(source, {
      cursorOffset,
      parser: "yaml",
      plugins: [pluginYaml],
      printWidth: 80, // Set the desired max line length
    });
  }
  const [prettier, pluginTypescript, pluginEsTree] = await Promise.all([
    import("prettier/standalone"),
    import("prettier/plugins/typescript"),
    import("prettier/plugins/estree"),
  ]);
  return await prettier.formatWithCursor(source, {
    cursorOffset,
    parser: "typescript",
    plugins: [pluginTypescript, pluginEsTree as any],
    printWidth: 80, // Set the desired max line length
  });
}

export function MonacoEditorImpl({
  value,
  onValueChange,
  language: _language,
  enableFancyToml,
  readOnly,
  filename,
  minHeight,
  maxHeightProportion,
  maxHeight,
  id,
  ...boxProps
}: MonacoEditorProps) {
  const language = (
    _language === "fancy_toml" && !enableFancyToml ? "toml" : _language
  ) as MonacoLanguage;

  const dimensions = useViewportSize();
  const [editor, setEditor] =
    useState<monaco.editor.IStandaloneCodeEditor | null>(null);
  const [instanceId] = useState(() => ++editorInstanceCounter);

  useEffect(() => {
    if (!editor) return;

    let node = editor.getDomNode();
    if (!node) return;

    const callback = (e: any) => {
      if (e.key === "Escape") {
        (document.activeElement as any)?.blur?.();
      }
    };

    node.addEventListener("keydown", callback);
    return () => node.removeEventListener("keydown", callback);
  }, [editor]);

  useEffect(() => {
    if (!isFormatLanguage(language)) return;
    if (!editor) return;
    // An action (unlike `addCommand`) is bound to this editor only, and
    // is removed with it / when the language changes. Off while the
    // editor is read only (see `formatDocumentAction`).
    const action = editor.addAction(
      formatDocumentAction({
        language,
        keybindings: [
          monaco.KeyMod.Alt | monaco.KeyMod.Shift | monaco.KeyCode.KeyF,
        ],
        readOnlyOption: monaco.editor.EditorOption.readOnly,
        format: formatWithCursor,
      }),
    );
    return () => action.dispose();
  }, [editor, language]);

  const line_count = value?.split(/\r\n|\r|\n/).length ?? 0;

  useEffect(() => {
    if (!editor) return;
    const contentHeight = line_count * 18 + 30;
    const containerNode = editor.getContainerDomNode();

    containerNode.style.height = `${Math.max(
      Math.min(
        contentHeight,
        Math.floor(dimensions.height * 0.75),
        maxHeightProportion
          ? Math.floor(maxHeightProportion * dimensions.height)
          : 10_000,
        maxHeight ?? 10_000,
      ),
      minHeight ?? MIN_EDITOR_HEIGHT,
    )}px`;
  }, [dimensions.height, editor, line_count]);

  const currentTheme = useComputedColorScheme();

  const options: monaco.editor.IStandaloneEditorConstructionOptions = {
    minimap: { enabled: false },
    // scrollbar: { alwaysConsumeMouseWheel: false },
    scrollBeyondLastLine: false,
    folding: false,
    automaticLayout: true,
    renderValidationDecorations: "on",
    renderLineHighlightOnlyWhenFocus: true,
    readOnly,
    tabSize: 2,
    detectIndentation: true,
    quickSuggestions: true,
    padding: {
      top: 15,
    },
  };

  return (
    <Box id={id} onKeyDown={(e) => e.stopPropagation()} {...boxProps}>
      <Editor
        language={language}
        value={value}
        theme={currentTheme}
        defaultPath={modelPath(instanceId, filename)}
        options={options}
        onChange={(v) => onValueChange?.(v ?? "")}
        onMount={(editor) => setEditor(editor)}
      />
    </Box>
  );
}

/**
 * The model uri of an editor showing `filename`. Unique per editor, so
 * two editors of eg. `app/compose.yaml` and `db/compose.yaml` never share
 * (and dispose) one model. It ends with the file's base name, which
 * name based language features match on (eg. a monaco-yaml schema's
 * `fileMatch` glob). Without a filename monaco makes a unique uri itself.
 */
function modelPath(instanceId: number, filename?: string) {
  if (!filename) return undefined;
  // Only the base name: a leading '/' would break the uri.
  const base = filename.split("/").pop() || "file";
  return `inmemory://mogh-ui/${instanceId}/${encodeURIComponent(base)}`;
}

const MIN_DIFF_HEIGHT = 100;
const MAX_DIFF_HEIGHT = 600;

export function MonacoDiffEditorImpl({
  original,
  modified,
  onModifiedValueChange,
  language: _language,
  enableFancyToml,
  readOnly,
  id,
  hideUnchangedRegions = true,
  ...boxProps
}: MonacoDiffEditorProps) {
  const language = (
    _language === "fancy_toml" && !enableFancyToml ? "toml" : _language
  ) as MonacoLanguage;

  const [editor, setEditor] =
    useState<monaco.editor.IStandaloneDiffEditor | null>(null);

  // The subscription outlives renders, so it calls the latest callback.
  const onModifiedValueChangeRef = useRef(onModifiedValueChange);
  useEffect(() => {
    onModifiedValueChangeRef.current = onModifiedValueChange;
  }, [onModifiedValueChange]);

  useEffect(() => {
    if (!editor) return;
    const modifiedEditor = editor.getModifiedEditor();
    const subscription = modifiedEditor.onDidChangeModelContent(() => {
      onModifiedValueChangeRef.current?.(modifiedEditor.getValue());
    });
    return () => subscription.dispose();
  }, [editor]);

  const original_line_count = original?.split(/\r\n|\r|\n/).length ?? 0;
  const modified_line_count = modified?.split(/\r\n|\r|\n/).length ?? 0;
  const line_count = Math.max(original_line_count, modified_line_count);

  useEffect(() => {
    if (!editor) return;
    const contentHeight = line_count * 18 + 30;
    const node = editor.getContainerDomNode();

    node.style.height = `${Math.max(
      Math.min(contentHeight, MAX_DIFF_HEIGHT),
      MIN_DIFF_HEIGHT,
    )}px`;
  }, [editor, line_count]);

  const currentTheme = useComputedColorScheme();

  const options: monaco.editor.IStandaloneDiffEditorConstructionOptions = {
    minimap: { enabled: true },
    scrollbar: { alwaysConsumeMouseWheel: false },
    scrollBeyondLastLine: false,
    hideUnchangedRegions: { enabled: hideUnchangedRegions },
    folding: false,
    automaticLayout: true,
    renderValidationDecorations: "on",
    renderLineHighlightOnlyWhenFocus: true,
    readOnly,
    padding: {
      top: 15,
    },
  };

  return (
    <Box id={id} onKeyDown={(e) => e.stopPropagation()} {...boxProps}>
      <DiffEditor
        language={language}
        original={original}
        modified={modified}
        theme={currentTheme}
        options={options}
        onMount={(editor) => setEditor(editor)}
      />
    </Box>
  );
}
