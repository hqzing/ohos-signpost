# ohos-signpost
Automatically sign the binary files in node\_modules on OpenHarmony.

The term "signpost" is a clever play on words:
1. **Sign** indicates that this is a signing tool, while **post** signifies that it is used during the **postinstall** phase.
2. Additionally, the word "signpost" itself means "a marke", which aligns perfectly with our process of adding markers to files during binary signing.

## Usage

Add this package to your `devDependencies` and call it as a `postinstall` script.
```json
{
  "devDependencies": {
    "ohos-signpost": "^0.0.1"
  },
  "scripts": {
    "postinstall": "ohos-signpost"
  }
}
```

When you run `npm install`, the script inside this package will be automatically triggered and will automatically sign all the binary files in `node_modules`.
