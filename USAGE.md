<div align="center">
<p>English | <a href="USAGE.zh-CN.md">简体中文</a></p>
</div>

# Detailed Usage

This guide describes the signing behavior, output, exit status, and strict mode of `ohos-signpost`. For installation and basic setup, see [README.md](README.md).

## Platform Behavior

- **On OpenHarmony**: The hook scans `node_modules` and signs eligible ELF binaries.
- **On other platforms**: The hook prints a warning and exits with status `0` without scanning or signing files.
- **Missing `node_modules`**: The hook exits with status `0` without doing any work. The same applies when the path exists but is not a directory.

## File Discovery

The hook looks for `node_modules` in the current working directory and processes files as follows:

1. It recursively visits directories and collects regular files. Symbolic links are skipped, so their targets are not signed.
2. Common source, text, and documentation files are skipped by extension or filename.
3. Files ending in `.so` or `.node` are checked for ELF magic bytes, regardless of their executable bits.
4. Files with other names are checked for ELF magic bytes only when at least one executable bit is set.

Only ELF64 files can be signed. A malformed or unsupported file selected as a candidate is counted as a signing failure. Up to 64 files are inspected concurrently to avoid exhausting file descriptors on large dependency trees.

## Signing and Output

Signing replaces the original file atomically and preserves its permission bits. Files that already contain a `.codesign` section are skipped rather than signed again.

After processing the candidates, the hook prints a summary:

```text
ohos-signpost: scanned 3, signed 2, skipped 1 (already signed), failed 0
```

The fields have the following meanings:

- `scanned`: The number of ELF candidates selected for signing. This is not the total number of files visited in `node_modules`.
- `signed`: The number of files newly signed in this run.
- `skipped`: The number of candidates skipped because they already contain a `.codesign` section.
- `failed`: The number of candidates that could not be signed.

Early exits, such as a missing `node_modules` directory or a non-OpenHarmony platform, do not print this summary.

## Exit Status and Strict Mode

### Default Mode

By default, the hook avoids blocking installation:

- A per-file signing failure prints a warning with the path and error message, then processing continues.
- A top-level failure, such as an unreadable `node_modules` directory, prints a warning.
- Both cases exit with status `0`.

### Strict Mode

Set `OHOS_SIGNPOST_STRICT=1` to make failures produce exit status `1`:

```sh
OHOS_SIGNPOST_STRICT=1 npm install
```

In strict mode, any per-file signing failure or top-level failure sets the exit status to `1`. All eligible files are still processed before a per-file failure causes the final exit.

Strict mode only changes failure handling. A missing `node_modules` directory, an already-signed file, or a non-OpenHarmony platform still results in status `0`. Unset variables and values other than `1` use the default behavior.

## Troubleshooting

- **Warning on a non-OpenHarmony platform**: This is expected. No files are changed, and the exit status is `0`.
- **File already signed**: The file is skipped and counted in `skipped`. No action is needed.
- **Failed to sign a file**: Check the error message and verify that the file is a valid ELF64 binary and is writable. This counts as a failure and produces status `1` only in strict mode.
- **`ohos-signpost failed`**: This indicates a top-level error, such as insufficient directory permissions. Check the reported path and error. The exit status depends on whether strict mode is enabled.
