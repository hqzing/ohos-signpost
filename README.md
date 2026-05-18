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
    "ohos-signpost": "^1.0.0"
  },
  "scripts": {
    "postinstall": "ohos-signpost"
  }
}
```

When you run `npm install`, the hook triggers automatically:

* **On OpenHarmony**: It scans `node_modules` and signs all valid ELF binaries (`.so`, `.node`, etc.).
* **On other platforms**: It safely bypasses the execution without blocking the installation process.
