#!/usr/bin/env node
const fs = require("node:fs").promises;
const { extname, basename, join, resolve } = require("node:path");
const { displaySignSync, selfSignSync, getBinarySignToolPath } = require("ohos-binary-sign");

if (process.platform != "openharmony") {
  console.warn(
    "Warning: ohos-signpost only works on OpenHarmony, it won't do anything on this platform."
  );
  return;
}

const knownElfExtName = new Set([".so", ".node"]);
const knownTextExtName = new Set([
  ".js",
  ".mjs",
  ".cjs",
  ".ts",
  ".mts",
  ".cts",
  ".jsx",
  ".tsx",
  ".json",
  ".md",
  ".txt",
  ".yml",
  ".yaml",
  ".html",
  ".map",
  ".css",
  ".gyp",
  ".gypi",
  ".c",
  ".cpp",
  ".cc",
]);
const knownTextBaseName = new Set([
  "license",
  "licence",
  "copying",
  "changelog",
  "changes",
  "authors",
  "contributors",
  "maintainers",
  "notice",
]);

// Concurrency pool
class Pool {
  /**
   * constructor
   * @param maxConcurrency Maximum Concurrency
   */
  constructor(maxConcurrency) {
    this.maxConcurrency = maxConcurrency;
    // The current number of running tasks
    this.running = 0;
    // waiting queue: { task, resolve, reject }
    this.queue = [];
  }

  /**
   * Submit a task and return a Promise
   * @param task
   * @returns {Promise<unknown>}
   */
  exec(task) {
    return new Promise((resolve, reject) => {
      this.queue.push({task, resolve, reject});
      this._drain();
    });
  }

  /**
   * Try to dequeue a task and execute it
   * @private
   */
  _drain() {
    if (this.running >= this.maxConcurrency || this.queue.length === 0) {
      return;
    }

    const {task, resolve, reject} = this.queue.shift();
    this.running++;

    Promise.resolve().then(() => task()).then(resolve).catch(reject).finally(() => {
      this.running--;
      this._drain();
    });
  }
}

async function hasElfMagic(filePath) {
  const elfMagic = Buffer.from([0x7f, 0x45, 0x4c, 0x46]);
  const handle = await fs.open(filePath, "r");
  try {
    const buf = Buffer.allocUnsafe(4);
    const { bytesRead } = await handle.read(buf, 0, 4, 0);
    return bytesRead === 4 && buf.compare(elfMagic) === 0;
  } finally {
    await handle.close();
  }
}

async function isElf(filePath) {
  try {
    const ext = extname(filePath);
    const base = basename(filePath).toLowerCase();

    // Skip common text files by extension
    if (knownTextExtName.has(ext)) return false;

    // Skip well-known text filenames
    if (knownTextBaseName.has(base)) return false;

    // Trust known ELF extensions
    if (knownElfExtName.has(ext)) return await hasElfMagic(filePath);

    // Use executable bit as last filter
    const stat = await fs.stat(filePath);
    if ((stat.mode & 0o111) === 0) return false;

    return await hasElfMagic(filePath);
  } catch {
    return false;
  }
}

// Collect all files in a directory
async function collectFiles(dir) {
  const files = [];

  async function walk(current) {
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const ent of entries) {
      if (ent.isSymbolicLink()) continue;

      const full = join(current, ent.name);
      if (ent.isDirectory()) {
        await walk(full);
      } else if (ent.isFile()) {
        files.push(full);
      }
    }
  }

  await walk(resolve(dir));
  return files;
}

// Collect ELF files from a file list
async function collectElf(filePaths) {
  const pool = new Pool(64);
  const results = [];

  for (const filePath of filePaths) {
    await pool.exec(async () => {
      try {
        if (await isElf(filePath)) {
          results.push(filePath)
        }
      } catch (err) {

      }
    });
  }

  return results;
}

// Batch add signatures to ELF files
function batchSign(filePaths) {
  for (const filePath of filePaths) {
    // The signing tool itself does not need to be signed
    if (filePath === getBinarySignToolPath()) {
      continue;
    }

    try {
      const stdout = displaySignSync({ inFile: filePath });
      if (stdout.includes("code signature is not found")) {
        selfSignSync(filePath);
        console.log(`Signature successfully added to: ${filePath}`);
      } else {
        console.warn(`Warning: File already signed, signing skipped: ${filePath}`);
      }
    } catch {
      console.warn(`Warning: Failed to process this file, signing skipped: ${filePath}`);
    }
  }
}

// Main process
(async () => {
  const nodeModulesPath = resolve(process.cwd(), "node_modules");
  const allFilePaths = await collectFiles(nodeModulesPath);
  const elfFilePaths = await collectElf(allFilePaths);
  batchSign(elfFilePaths);
})();

