import { registerHooks } from "node:module";

// The sources' relative imports are extensionless, left for the bundler
// (see README). Resolves them to their .ts files, like it does.
// Register this first, then load the sources with `await import()`:
// static imports are all resolved before any module runs.
registerHooks({
  resolve(specifier, context, nextResolve) {
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
