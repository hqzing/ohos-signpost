"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  hasCodesignSection,
  parseElfHeader,
  signElf,
  signFileAtomic,
  stripCodesign,
} = require("../lib/selfsign.js");

const projectRoot = path.resolve(__dirname, "..");
const cliPath = path.join(projectRoot, "bin", "ohos-signpost.js");

function align(value, alignment) {
  return Math.ceil(value / alignment) * alignment;
}

function createUnsignedElf64() {
  const text = Buffer.from([0x1f, 0x20, 0x03, 0xd5]);
  const shstrtab = Buffer.from("\0.text\0.shstrtab\0", "latin1");
  const textOffset = 64;
  const shstrtabOffset = textOffset + text.length;
  const sectionHeaderOffset = align(shstrtabOffset + shstrtab.length, 8);
  const sectionHeaderCount = 3;
  const elf = Buffer.alloc(sectionHeaderOffset + sectionHeaderCount * 64);

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
  elf.writeUInt16LE(64, 58);
  elf.writeUInt16LE(sectionHeaderCount, 60);
  elf.writeUInt16LE(2, 62);

  text.copy(elf, textOffset);
  shstrtab.copy(elf, shstrtabOffset);

  const textSection = sectionHeaderOffset + 64;
  elf.writeUInt32LE(1, textSection);
  elf.writeUInt32LE(1, textSection + 4);
  elf.writeBigUInt64LE(6n, textSection + 8);
  elf.writeBigUInt64LE(BigInt(textOffset), textSection + 24);
  elf.writeBigUInt64LE(BigInt(text.length), textSection + 32);
  elf.writeBigUInt64LE(4n, textSection + 48);

  const shstrtabSection = sectionHeaderOffset + 128;
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
