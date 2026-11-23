"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  buildDescriptor,
  checkSelfsign,
  findSectionByName,
  hasCodesignSection,
  merkleRootHash,
  parseElfHeader,
  signElf,
  signFileAtomic,
  stripCodesign,
} = require("../lib/selfsign.js");

const CODESIGN_NAME = Buffer.from(".codesign\0", "latin1");

const projectRoot = path.resolve(__dirname, "..");
const cliPath = path.join(projectRoot, "bin", "ohos-signpost.js");

// Fault-injection bootstrap, run inline via `node -e` so the test layout stays
// flat. A real chmod 000 is not reliable when the OpenHarmony CI runs as root.
const EACCES_BOOTSTRAP = `
"use strict";
const fs = require("node:fs").promises;
const origReaddir = fs.readdir;
fs.readdir = async function (p, ...args) {
  if (String(p) === process.env.OHOS_SIGNPOST_TEST_EACCES_PATH) {
    const err = new Error("EACCES: permission denied, scandir '" + p + "'");
    err.code = "EACCES";
    throw err;
  }
  return origReaddir.call(this, p, ...args);
};
const origStat = fs.stat;
fs.stat = async function (p, ...args) {
  if (String(p) === process.env.OHOS_SIGNPOST_TEST_STAT_EACCES_PATH) {
    const err = new Error("EACCES: permission denied, stat '" + p + "'");
    err.code = "EACCES";
    throw err;
  }
  return origStat.call(this, p, ...args);
};
require(process.env.OHOS_SIGNPOST_TEST_CLI_PATH);
`;

function runCliWithFaultInjection(directory, faultEnv, strict) {
  return spawnSync(process.execPath, ["-e", EACCES_BOOTSTRAP], {
    cwd: directory,
    encoding: "utf8",
    env: {
      ...process.env,
      OHOS_SIGNPOST_TEST_CLI_PATH: cliPath,
      ...faultEnv,
      OHOS_SIGNPOST_STRICT: strict ? "1" : "0",
    },
  });
}

function align(value, alignment) {
  return Math.ceil(value / alignment) * alignment;
}

function createUnsignedElf64(shentsize = 64) {
  const text = Buffer.from([0x1f, 0x20, 0x03, 0xd5]);
  const shstrtab = Buffer.from("\0.text\0.shstrtab\0", "latin1");
  const textOffset = 64;
  const shstrtabOffset = textOffset + text.length;
  const sectionHeaderOffset = align(shstrtabOffset + shstrtab.length, 8);
  const sectionHeaderCount = 3;
  const elf = Buffer.alloc(sectionHeaderOffset + sectionHeaderCount * shentsize);

  elf.set([0x7f, 0x45, 0x4c, 0x46], 0);
  elf[4] = 2;
  elf[5] = 1;
  elf[6] = 1;
  elf.writeUInt16LE(2, 16);
  elf.writeUInt16LE(183, 18);
  elf.writeUInt32LE(1, 20);
  elf.writeBigUInt64LE(0x400000n, 24);
  elf.writeBigUInt64LE(BigInt(sectionHeaderOffset), 40);
  elf.writeUInt16LE(64, 52);
  elf.writeUInt16LE(56, 54);
  elf.writeUInt16LE(shentsize, 58);
  elf.writeUInt16LE(sectionHeaderCount, 60);
  elf.writeUInt16LE(2, 62);

  text.copy(elf, textOffset);
  shstrtab.copy(elf, shstrtabOffset);

  const textSection = sectionHeaderOffset + shentsize;
  elf.writeUInt32LE(1, textSection);
  elf.writeUInt32LE(1, textSection + 4);
  elf.writeBigUInt64LE(6n, textSection + 8);
  elf.writeBigUInt64LE(BigInt(textOffset), textSection + 24);
  elf.writeBigUInt64LE(BigInt(text.length), textSection + 32);
  elf.writeBigUInt64LE(4n, textSection + 48);

  const shstrtabSection = sectionHeaderOffset + 2 * shentsize;
  elf.writeUInt32LE(7, shstrtabSection);
  elf.writeUInt32LE(3, shstrtabSection + 4);
  elf.writeBigUInt64LE(BigInt(shstrtabOffset), shstrtabSection + 24);
  elf.writeBigUInt64LE(BigInt(shstrtab.length), shstrtabSection + 32);
  elf.writeBigUInt64LE(1n, shstrtabSection + 48);

  return elf;
}

function makeTempDir(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ohos-signpost-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function writeFixture(directory, relativePath, contents, mode = 0o644) {
  const filePath = path.join(directory, relativePath);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, contents);
  fs.chmodSync(filePath, mode);
  return filePath;
}

function countCodesignSections(elf) {
  const { e_shoff, e_shnum, e_shstrndx } = parseElfHeader(elf);
  let count = 0;
  for (let index = 0; index < e_shnum; index += 1) {
    const entryOffset = e_shoff + index * 64;
    const nameOffset = elf.readUInt32LE(entryOffset);
    const shstrEntry = e_shoff + e_shstrndx * 64;
    const shstrOffset = Number(elf.readBigUInt64LE(shstrEntry + 24));
    const shstrSize = Number(elf.readBigUInt64LE(shstrEntry + 32));
    if (nameOffset + 10 > shstrSize) continue;
    if (
      elf.subarray(shstrOffset + nameOffset, shstrOffset + nameOffset + 10)
        .equals(Buffer.from(".codesign\0", "latin1"))
    ) {
      count += 1;
    }
  }
  return count;
}

function findCodesignOffset(elf) {
  const { e_shoff, e_shentsize, e_shnum, e_shstrndx } = parseElfHeader(elf);
  const entry = findSectionByName(
    elf,
    e_shoff,
    e_shentsize,
    e_shnum,
    e_shstrndx,
    CODESIGN_NAME,
  );
  assert.notEqual(entry, -1);
  return Number(elf.readBigUInt64LE(entry + 24));
}

test("signElf adds a self-signature and marks the binary as signed", () => {
  const unsigned = createUnsignedElf64();
  const signed = signElf(unsigned, false);

  assert.equal(hasCodesignSection(unsigned), false);
  assert.equal(hasCodesignSection(signed), true);
  assert.equal(countCodesignSections(signed), 1);
  assert.equal(signed.subarray(0, 4).toString("hex"), "7f454c46");
});

test("signFileAtomic preserves permissions and supports forced re-signing", (t) => {
  const directory = makeTempDir(t);
  const filePath = writeFixture(
    directory,
    "native/addon.node",
    createUnsignedElf64(),
    0o751,
  );

  signFileAtomic(filePath, false);
  assert.equal(hasCodesignSection(fs.readFileSync(filePath)), true);
  assert.equal(fs.statSync(filePath).mode & 0o7777, 0o751);
  assert.throws(
    () => signFileAtomic(filePath, false),
    /already has a \.codesign section/,
  );

  signFileAtomic(filePath, true);
  const signed = fs.readFileSync(filePath);
  assert.equal(countCodesignSections(signed), 1);
  assert.equal(fs.statSync(filePath).mode & 0o7777, 0o751);
});

test("stripCodesign restores a signable ELF without a .codesign section", (t) => {
  const directory = makeTempDir(t);
  const filePath = writeFixture(
    directory,
    "native/addon.node",
    createUnsignedElf64(),
  );
  signFileAtomic(filePath, false);

  const result = stripCodesign(fs.readFileSync(filePath));
  assert.equal(result.removed, true);
  assert.equal(hasCodesignSection(result.out), false);
  assert.doesNotThrow(() => parseElfHeader(result.out));

  fs.writeFileSync(filePath, result.out);
  assert.doesNotThrow(() => signFileAtomic(filePath, false));
});

test("signElf rejects malformed input", () => {
  assert.throws(() => signElf(Buffer.from("not an ELF"), false), /not ELF64/);
});

test(
  "CLI signs eligible node_modules files and skips ineligible entries",
  { skip: process.platform !== "openharmony" && "requires OpenHarmony" },
  (t) => {
    const directory = makeTempDir(t);
    const nodeModules = path.join(directory, "node_modules");
    const unsigned = createUnsignedElf64();

    const library = writeFixture(
      nodeModules,
      "pkg/native/library.so",
      unsigned,
      0o755,
    );
    const addon = writeFixture(
      nodeModules,
      "pkg/native/addon.node",
      unsigned,
      0o644,
    );
    const executable = writeFixture(
      nodeModules,
      "pkg/bin/tool",
      unsigned,
      0o755,
    );
    const nonExecutable = writeFixture(
      nodeModules,
      "pkg/bin/data",
      unsigned,
      0o644,
    );
    const disguisedText = writeFixture(
      nodeModules,
      "pkg/text/fake.node",
      "plain text",
      0o755,
    );
    const alreadySigned = writeFixture(
      nodeModules,
      "pkg/native/pre-signed.node",
      unsigned,
      0o755,
    );
    signFileAtomic(alreadySigned, false);
    const signedBeforeCli = fs.readFileSync(alreadySigned);

    const externalElf = writeFixture(
      directory,
      "outside.so",
      unsigned,
      0o755,
    );
    const symlink = path.join(nodeModules, "pkg/native/linked.so");
    fs.symlinkSync(externalElf, symlink);

    const result = spawnSync(process.execPath, [cliPath], {
      cwd: directory,
      encoding: "utf8",
    });

    assert.equal(result.status, 0, result.stderr);
    assert.equal(hasCodesignSection(fs.readFileSync(library)), true);
    assert.equal(hasCodesignSection(fs.readFileSync(addon)), true);
    assert.equal(hasCodesignSection(fs.readFileSync(executable)), true);
    assert.equal(hasCodesignSection(fs.readFileSync(nonExecutable)), false);
    assert.equal(fs.readFileSync(disguisedText, "utf8"), "plain text");
    assert.deepEqual(fs.readFileSync(alreadySigned), signedBeforeCli);
    assert.equal(fs.lstatSync(symlink).isSymbolicLink(), true);
    assert.equal(hasCodesignSection(fs.readFileSync(externalElf)), false);
    assert.match(result.stderr, /already signed/);
  },
);

test(
  "CLI strict mode fails on top-level errors (EACCES reading node_modules)",
  { skip: process.platform !== "openharmony" && "requires OpenHarmony" },
  (t) => {
    const directory = makeTempDir(t);
    const nodeModules = path.join(directory, "node_modules");
    fs.mkdirSync(nodeModules, { recursive: true });

    const runCli = (strict) =>
      runCliWithFaultInjection(
        directory,
        { OHOS_SIGNPOST_TEST_EACCES_PATH: nodeModules },
        strict,
      );

    const strict = runCli(true);
    assert.equal(strict.status, 1, strict.stderr);
    assert.match(strict.stderr, /ohos-signpost failed/);

    const lenient = runCli(false);
    assert.equal(lenient.status, 0, lenient.stderr);
    assert.match(lenient.stderr, /ohos-signpost failed/);
  },
);

test(
  "CLI strict mode fails when fs.stat(node_modules) fails with EACCES",
  { skip: process.platform !== "openharmony" && "requires OpenHarmony" },
  (t) => {
    const directory = makeTempDir(t);
    const nodeModules = path.join(directory, "node_modules");
    fs.mkdirSync(nodeModules, { recursive: true });

    const runCli = (strict) =>
      runCliWithFaultInjection(
        directory,
        { OHOS_SIGNPOST_TEST_STAT_EACCES_PATH: nodeModules },
        strict,
      );

    const strict = runCli(true);
    assert.equal(strict.status, 1, strict.stderr);
    assert.match(strict.stderr, /ohos-signpost failed/);

    const lenient = runCli(false);
    assert.equal(lenient.status, 0, lenient.stderr);
    assert.match(lenient.stderr, /ohos-signpost failed/);
  },
);

test("checkSelfsign validates a fresh signature and detects tampering", () => {
  const signed = signElf(createUnsignedElf64(), false);
  assert.deepEqual(checkSelfsign(signed), { ok: true, reason: null });

  const csOff = findCodesignOffset(signed);

  const badSize = Buffer.from(signed);
  badSize.writeBigUInt64LE(BigInt(signed.length + 4096), csOff + 8 + 8);
  assert.deepEqual(checkSelfsign(badSize), {
    ok: false,
    reason: "fileSize mismatch",
  });

  const badRoot = Buffer.from(signed);
  badRoot[csOff + 8 + 16] ^= 0xff;
  assert.deepEqual(checkSelfsign(badRoot), {
    ok: false,
    reason: "merkle root mismatch",
  });

  const badSig = Buffer.from(signed);
  badSig[csOff + 8 + 256] ^= 0xff;
  assert.deepEqual(checkSelfsign(badSig), {
    ok: false,
    reason: "signature mismatch",
  });
});

test("parseElfHeader and signing accept extended section headers", () => {
  const elf = createUnsignedElf64(72);
  const header = parseElfHeader(elf);
  assert.equal(header.e_shentsize, 72);

  const signed = signElf(elf, false);
  assert.equal(hasCodesignSection(signed), true);
  assert.deepEqual(checkSelfsign(signed), { ok: true, reason: null });
});

test("parseElfHeader rejects malformed input", () => {
  assert.throws(() => parseElfHeader(Buffer.from("not an ELF")), /not ELF64/);
  assert.throws(() => parseElfHeader(Buffer.alloc(64)), /not ELF64/);
});

test("merkleRootHash is deterministic and sensitive to content changes", () => {
  const a = Buffer.alloc(8192, 0x11);
  const b = Buffer.from(a);
  b[100] = 0x22;

  const first = merkleRootHash(a, 4096, 4096);
  const second = merkleRootHash(a, 4096, 4096);
  const changed = merkleRootHash(b, 4096, 4096);

  assert.deepEqual(first, second);
  assert.equal(first.root.length, 32);
  assert.notDeepEqual(first.root, changed.root);
});

test("buildDescriptor writes the documented field offsets", () => {
  const root = Buffer.alloc(32, 0xab);
  const descriptor = buildDescriptor(32, 12345, root, 0x10);

  assert.equal(descriptor.length, 256);
  assert.equal(descriptor[0], 1);
  assert.equal(descriptor[1], 1);
  assert.equal(descriptor[2], 12);
  assert.equal(descriptor[3], 0);
  assert.equal(descriptor.readUInt32LE(4), 32);
  assert.equal(Number(descriptor.readBigUInt64LE(8)), 12345);
  assert.deepEqual(descriptor.subarray(16, 48), root);
  assert.equal(descriptor.readUInt32LE(112), 0x10);
  assert.equal(descriptor[255], 3);
});

test("hasCodesignSection returns false for malformed input", () => {
  assert.equal(hasCodesignSection(Buffer.from("not an ELF")), false);
  assert.equal(hasCodesignSection(Buffer.alloc(64)), false);
});
