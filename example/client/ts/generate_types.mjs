import { exec } from "child_process";
import { readFileSync, writeFileSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const example = path.resolve(__dirname, "../..");
const types_path = path.join(__dirname, "src/types.ts");

console.log("generating typescript types...");

// The entities and requests come from the client crate,
// the request enums (`ReadRequest`, ...) from the server api.
const gen_command = [
  "RUST_BACKTRACE=1 typeshare",
  JSON.stringify(path.join(example, "client/rs")),
  JSON.stringify(path.join(example, "server/src/api")),
  "--lang=typescript",
  `--output-file=${JSON.stringify(types_path)}`,
].join(" ");

exec(gen_command, (error, _stdout, stderr) => {
  if (error) {
    console.error(error, stderr);
    process.exit(1);
  }
  console.log("generated types using typeshare");
  fix_types();
  console.log("finished.");
});

function fix_types() {
  const contents = readFileSync(types_path);
  const fixed = contents
    .toString()
    // Apply fixes
    .replaceAll("IndexSet", "Array")
    .replaceAll("IndexMap", "Record");
  writeFileSync(types_path, fixed);
}
