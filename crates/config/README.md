# Mogh Config

Module for comprehensive loading of strongly typed configuration files using `std::fs` and `serde`.

- Supports parsing JSON, YAML, TOML, and env files (`.env`, `*.env`).
- Supports merging final configuration from multiple supplied files / directories.
- Supports `${ENV_VAR}` and `$(command)` interpolation in values of
  local toml / yaml / json files (not in env files or in files loaded
  from Cicada, whose values are secrets taken verbatim). `$(command)` runs
  a single command word (letters, digits, `_`) without arguments, eg.
  `$(hostname)`; anything else, like `$(cat /run/secrets/db)` or
  `${VAR:-default}`, is kept as written, with a warning naming the key.
- Coerces string values into the field's type the way `envy` reads the
  process environment: numbers, booleans, comma separated lists into
  `Vec`s, `Option`, enum variants. Not inside `#[serde(flatten)]` fields
  or untagged / internally tagged enums, which serde buffers as-is.

Priority (later overrides earlier): `paths` in order given. Within a directory,
its own files (by wildcard, then name; a file matching several wildcards takes
the last one it matches), then each path in the include file in the order
listed, recursively, so includes override the directory's own files. A file
reached twice (listed as a path and found by a directory scan) is loaded once,
at its later position. A wildcard which doesn't compile is an error
(`Error::InvalidWildcard`), never a dropped filter.

```rust,no_run
use std::path::Path;

use mogh_config::ConfigLoader;

#[derive(serde::Deserialize)]
struct Config {
  title: String,
  aliases: Vec<String>,
  endpoint: String,
  use_option: bool,
}

let config = (ConfigLoader {
  // Read config files from a directory
  paths: &[Path::new("./configs")],
  match_wildcards: &["*config*.toml"],
  // It won't recurse into subdirectories unless they include '.configinclude' file
  include_file_name: ".configinclude",
  merge_nested: true,
  extend_array: true,
  debug_print: true,
})
.load::<Config>()
.expect("Failed to parse config from path");
```

Merging: each source merges over the ones before it, and is never dropped
over a type conflict. With `merge_nested`, two objects merge key by key; with
`extend_array`, an array extends the one before it. A `null` (a yaml section
with every line commented out) keeps the object or array before it. Any other
value replaces the one before it, as it does without those flags, and a value
the config type can't take fails the final deserialization with its path and
type (never the value). `mogh_config::merge_objects` keeps its stricter rules
(a type mismatch is an error) for callers merging anything else.

## Env files

An env file is a flat configuration source: `NAME=value` lines, `#`
comments, optional `export`, values unquoted, single quoted (literal) or
double quoted with `\n` / `\r` / `\t` / `\"` / `\\` escapes. Names are lowercased
to match struct fields (`DB_PASSWORD=x` fills `db_password`) and dots
nest (`DATABASE.ADDRESS=x` fills `database.address`), values are strings
coerced into the field's type, so the same struct reads a toml file, an
env file, or both merged. A name with an empty segment cannot nest
(`.dockerconfigjson`, `A..B`, `A.`), so it is kept whole as one flat key,
lowercased (`.dockerconfigjson`, `a..b`; reach it with
`#[serde(rename = ".dockerconfigjson")]`). Nesting stops at 32 segments: a
longer name is one flat key too. A name that is both a value and
an object (`DATABASE=x` next to `DATABASE.ADDRESS=y`), or two names equal
once lowercased (`DB` and `db`), is an error naming the line and both
names. Values are never interpolated: they are secrets, not templates.
A parse error names the line (and entry) and what was expected, never
the value: not even the character after an unsupported escape.

```sh
# .env, listed in the paths after the defaults
PORT=8080
ALLOWED_HOSTS=a.example.com,b.example.com
DATABASE.ADDRESS=db.example.com:5432
DATABASE.USERNAME=app
DATABASE.PASSWORD="hunter2"
```

A comma separated value from an env file merged onto an array from an earlier
source extends it under `extend_array` (`HOSTS=b,c` onto `["a"]` gives
`["a", "b", "c"]`), and replaces it otherwise (the final deserialization
splits it into the list).

List an env file as a path, or match it with a directory wildcard
(`*.env`, `.env`): a directory scanned without wildcards skips env files,
so a compose `.env` next to the config files is not read by accident.
`.env` has no extension for `Path::extension`, and is recognized by name.

## Features

- `cicada` (off by default since 3.0): load config from [Cicada](https://github.com/moghtech/cicada)
  with `cicada:` paths, eg. `cicada://filesystem/config.yaml?env=prod` for a
  file interpolated with the `prod` environment, or `cicada://.env?env=base+prod`
  for the environments themselves as an env file. It pulls the Cicada client
  into the build, so it is opt in:
  `mogh_config = { version = "3", features = ["cicada"] }`.
  A `cicada:` line in an include file is a source like a `cicada:` path.
  Without the feature a `cicada:` path is an error, not a skipped path. With
  it, a `cicada:` source which fails to load (`Error::CicadaLoad`: Core
  unreachable, the device not onboarded or not granted the environments, the
  file missing) or to parse is an error too, rather than starting the app with
  its defaults; only a missing or malformed local file is skipped. The loader is
  re-exported as `mogh_config::cicada`, so an application can start its
  background (`cicada::spawn()`, or `CICADA_BACKGROUND=true`) and react to
  configuration changes (`cicada::on_change`, `cicada::subscribe`) without
  depending on `cicada_loader` itself. Because the loader's API is part of
  `mogh_config`'s, a `cicada_loader` minor (`0.x`) bump ships as a
  `mogh_config` major release, while a loader patch bump stays a patch
  release.
