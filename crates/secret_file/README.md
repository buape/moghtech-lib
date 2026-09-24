# Mogh Secret File

Helpers for parsing secret values from file contents.

For example, used to parse secrets from the files specified in env variable ending in `_FILE`.

Compatible with docker compose secrets,
see [https://docs.docker.com/compose/how-tos/use-secrets/](https://docs.docker.com/compose/how-tos/use-secrets/).

Also contains helpers for writing these files (`write` feature, plus `tokio` for `write_async`):

- New files are created with `0600` permissions (on unix, other platforms use their default permissions).
- The contents are written to a temp file beside the path and renamed onto it,
  so readers never see a partial file and a failed write leaves the existing file untouched.
  The file and its directory are synced, so a completed write survives a crash.
- An existing file keeps its permissions, and on unix its owner and group.
  If these can't be kept, and the file can't be written in place either (see below), the write fails.
- A symlink at the path is **not followed**: it is replaced by a new `0600` file, and the file it points to is left untouched,
  so a planted link can't redirect the write. The same goes for anything else which is not a regular file (eg. a fifo).
  To write through a trusted link, resolve it first (eg. `std::fs::canonicalize`) and write the resolved path.
- Files which can't be replaced without changing what they are, are written in place instead, which is not atomic:
  - bind mounted files (eg. docker / kubernetes single file mounts),
  - files in directories which can't be written to,
  - files whose owner / group can't be given to a new file (eg. a non-root process writing another user's file),
    except another user's file in a sticky directory (eg. `/tmp`), which fails like a rename would,
  - hard linked files, when only the directory's owner (root or the file's owner) can write to the directory.
    Otherwise, or if the file is read only, the link is split off.
- Don't write to paths in directories that untrusted users can write to, as they can plant the file which is written.
- `write_async` runs on the tokio blocking thread pool. A dropped future doesn't cut the write off halfway,
  it completes in the background.
