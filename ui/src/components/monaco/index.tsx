import { lazy, Suspense } from "react";
import { MonacoDiffEditorProps, MonacoEditorProps } from "./common";

export * from "./common";

// The editor implementation pulls in monaco-editor / @monaco-editor/react,
// so it is loaded lazily to keep it out of consumers' entry chunks.
const MonacoEditorInner = lazy(() =>
  import("./editor").then((m) => ({ default: m.MonacoEditorImpl })),
);
const MonacoDiffEditorInner = lazy(() =>
  import("./editor").then((m) => ({ default: m.MonacoDiffEditorImpl })),
);

export function MonacoEditor(props: MonacoEditorProps) {
  return (
    <Suspense fallback={null}>
      <MonacoEditorInner {...props} />
    </Suspense>
  );
}

export function MonacoDiffEditor(props: MonacoDiffEditorProps) {
  return (
    <Suspense fallback={null}>
      <MonacoDiffEditorInner {...props} />
    </Suspense>
  );
}
