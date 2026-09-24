import { execFile } from "child_process";
import { readFileSync, writeFileSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Run from the repository root (where typeshare.toml is),
// whatever the working directory.
const root = path.resolve(__dirname, "../../..");
const types_path = path.join(__dirname, "src/types.ts");

console.log("generating typescript types...");

execFile(
  "typeshare",
  ["./auth", "--lang=typescript", `--output-file=${types_path}`],
  { cwd: root, env: { ...process.env, RUST_BACKTRACE: "1" } },
  (error) => {
    if (error) {
      console.error(error);
      // Fail the chained build (`... && npm run build`),
      // rather than building the stale types.
      console.error("failed to generate types with typeshare");
      process.exitCode = 1;
      return;
    }
    console.log("generated types using typeshare");
    fix_types();
    console.log("finished.");
  },
);

function fix_types() {
  const contents = readFileSync(types_path);
  const fixed = contents
    .toString()
    // Apply fixes
    .replaceAll("IndexSet", "Array")
    .replaceAll("IndexMap", "Record");
  writeFileSync(types_path, fixed);
}
