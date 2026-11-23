# ohos-signpost

Automatically sign the binary files in `node_modules` on OpenHarmony.

The term "signpost" is a play on words:
1. **Sign** indicates that this is a signing tool, while **post** signifies that it is used during the `postinstall` phase.
2. Additionally, the word "signpost" itself means "a marker", which aligns with the process of adding signature markers to ELF files during binary signing.

## Usage

Add this package to your `devDependencies` and invoke it inside the `postinstall` script.

```json
{
  "devDependencies": {
    "ohos-signpost": "^1.1.2"
  },
  "scripts": {
    "postinstall": "ohos-signpost"
  }
}
```

When you run `npm install`, the hook triggers automatically:

* **On OpenHarmony**: It scans `node_modules` and signs all valid ELF binaries (`.so`, `.node`, etc.).
* **On other platforms**: It safely bypasses the execution without blocking the installation process.

### Behavior details

- Only ELF64 files are signed. Files ending in `.so` or `.node` are checked by ELF magic bytes; other files are considered only when they have an executable bit set.
- Files that already contain a `.codesign` section are skipped rather than re-signed.
- If the project has no `node_modules` directory, the hook is a no-op and exits successfully.
- Signing failures do not block installation by default; a summary of signed, skipped, and failed files is printed at the end of the run.
