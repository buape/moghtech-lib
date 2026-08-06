import "./init";

import { useEffect, useState } from "react";
import { DiffEditor, Editor } from "@monaco-editor/react";
import * as monaco from "monaco-editor";
import { useViewportSize } from "@mantine/hooks";
import { Box, useComputedColorScheme } from "@mantine/core";
import {
  MonacoDiffEditorProps,
  MonacoEditorProps,
  MonacoLanguage,
} from "./common";

const MIN_EDITOR_HEIGHT = 56;

/** Prettier embeds the full typescript parser - only load it on demand. */
async function formatWithCursor(
  language: "yaml" | "typescript" | "javascript",
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
    if (
      language !== "typescript" &&
      language !== "javascript" &&
      language !== "yaml"
    )
      return;
    if (!editor) return;
    editor.addCommand(
      monaco.KeyMod.Alt | monaco.KeyMod.Shift | monaco.KeyCode.KeyF,
      async () => {
        if (!editor) return;
        const model = editor.getModel();
        if (!model) return;
        const position = editor.getPosition();
        let beforeOffset = (position && model.getOffsetAt(position)) ?? 0;
        const curr = editor.getValue();
        const { formatted, cursorOffset } = await formatWithCursor(
          language,
          curr,
          beforeOffset,
        );
        editor.setValue(formatted);
        editor.setPosition(model.getPositionAt(cursorOffset));
      },
    );
  }, [editor]);

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
        defaultPath={defaultPath(filename)}
        options={options}
        onChange={(v) => onValueChange?.(v ?? "")}
        onMount={(editor) => setEditor(editor)}
      />
    </Box>
  );
}

function defaultPath(filename?: string) {
  if (!filename) return undefined;
  // Extract only the filename part of path,
  // avoiding critical issue when path starts with '/'
  const split = filename.split("/");
  return split[split.length - 1];
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
        onMount={(editor) => {
          const modifiedEditor = editor.getModifiedEditor();
          modifiedEditor.onDidChangeModelContent((_) => {
            onModifiedValueChange?.(modifiedEditor.getValue());
          });
          setEditor(editor);
        }}
      />
    </Box>
  );
}
