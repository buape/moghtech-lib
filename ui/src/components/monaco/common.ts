import { BoxProps } from "@mantine/core";

export type MonacoLanguage =
  | "yaml"
  | "toml"
  | "fancy_toml"
  | "json"
  | "key_value"
  | "ini"
  | "string_list"
  | "shell"
  | "dockerfile"
  | "rust"
  | "javascript"
  | "typescript";

const LANGUAGE_EXTENSIONS: Record<MonacoLanguage, string[]> = {
  yaml: [".yaml", ".yml"],
  toml: [".toml"],
  fancy_toml: [],
  json: [".json"],
  key_value: [".env", ".conf"],
  ini: [".ini"],
  string_list: [],
  shell: [".sh", ".bash", ".zsh"],
  dockerfile: ["Dockerfile"],
  rust: [".rs"],
  javascript: [".js", ".jsx", ".mjs", ".cjs"],
  typescript: [".ts", ".tsx"],
};

export function languageFromPath(path: string) {
  for (const [lang, extensions] of Object.entries(LANGUAGE_EXTENSIONS)) {
    for (const extension of extensions) {
      if (path.endsWith(extension)) {
        return lang as MonacoLanguage;
      }
    }
  }
  return undefined;
}

export interface MonacoEditorProps extends BoxProps {
  value: string | undefined;
  onValueChange?: (value: string) => void;
  language: MonacoLanguage | undefined;
  enableFancyToml?: boolean;
  filename?: string;
  readOnly?: boolean;
  minHeight?: number;
  /** Define max height as proportion of dimension height. Should be between 0 and 1. */
  maxHeightProportion?: number;
  maxHeight?: number;
  id?: string;
}

export interface MonacoDiffEditorProps extends BoxProps {
  original: string | undefined;
  modified: string | undefined;
  onModifiedValueChange?: (value: string) => void;
  language: MonacoLanguage | undefined;
  enableFancyToml?: boolean;
  readOnly?: boolean;
  id?: string;
  hideUnchangedRegions?: boolean;
}
