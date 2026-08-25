#!/usr/bin/env node
// Copyright (C) 2026 hqzing
// SPDX-License-Identifier: 0BSD
// Repository: https://github.com/hqzing/ohos-bst-light
//
// Licensed under the BSD Zero Clause License.

/*
 * selfsign.js — 轻量级 OpenHarmony 二进制自签名工具
 *
 * 用法:
 *     node selfsign.js <input_elf> [output_elf] [--force] [--strip]
 *         缺省 output 时, inplace 改写 input.
 *         --force : 若已含 .codesign 段, 先剥离再重签
 *         --strip : 仅剥离 .codesign 段, 不做签名
 */
"use strict";

const crypto = require("crypto");
const fs = require("fs");

const DESC_SIZE = 256;
const PAGE_SIZE = 4096;
const FLAG_SELF_SIGN = 0x10;
const FS_VERITY_DESCRIPTOR_TYPE = 1;
const HASH_OUT = 32; // SHA-256 输出字节数

// ELF64 header 字段偏移
const E_SHOFF = 0x28;
const E_SHENTSIZE = 0x3a;
const E_SHNUM = 0x3c;
const E_SHSTRNDX = 0x3e;

const CODESIGN_NAME = Buffer.from(".codesign\0", "latin1"); // 含结尾 NUL, 共 10 字节

// ─────────────────────── 字节读写工具 ───────────────────────
// 说明: 所有偏移与 64 位值一律用 JS Number (安全整数到 2^53),
// 与 Node Buffer 的 offset 参数类型要求一致, 且远大于任意 ELF 文件大小。
function sha256(b) {
  return crypto.createHash("sha256").update(b).digest();
}

function readU16(buf, off) {
  return buf.readUInt16LE(off);
}

function readU32(buf, off) {
  return buf.readUInt32LE(off);
}

function readU64(buf, off) {
  const lo = buf.readUInt32LE(off);
  const hi = buf.readUInt32LE(off + 4);
  return hi * 0x100000000 + lo;
}

function writeU16(buf, off, v) {
  buf.writeUInt16LE(v, off);
}

function writeU32(buf, off, v) {
  buf.writeUInt32LE(v >>> 0, off);
}

function writeU64(buf, off, v) {
  const lo = v >>> 0;
  const hi = Math.floor(v / 0x100000000);
  buf.writeUInt32LE(lo, off);
  buf.writeUInt32LE(hi, off + 4);
}

function alignUp(v, a) {
  return Math.ceil(v / a) * a;
}

// ─────────────────── ELF 预清洗/标准化 (非签名必需) ───────────────────
function parseElfHeader(elf) {
  // 校验并解析 ELF64 header (只读预检). 返回 {e_shoff, e_shnum, e_shstrndx}
  if (
    elf.length < 64 ||
    elf[0] !== 0x7f ||
    elf[1] !== 0x45 ||
    elf[2] !== 0x4c ||
    elf[3] !== 0x46 ||
    elf[4] !== 2
  ) {
    throw new Error("not ELF64");
  }
  const e_shoff = readU64(elf, E_SHOFF);
  const e_shentsize = readU16(elf, E_SHENTSIZE);
  const e_shnum = readU16(elf, E_SHNUM);
  const e_shstrndx = readU16(elf, E_SHSTRNDX);
  if (
    e_shentsize !== 64 ||
    e_shoff === 0 ||
    e_shnum === 0 ||
    e_shstrndx >= e_shnum
  ) {
    throw new Error("ELF has no usable section header table");
  }
  if (
    e_shoff > elf.length ||
    e_shnum > Math.floor((elf.length - e_shoff) / 64)
  ) {
    throw new Error("section header table out of bounds");
  }
  return { e_shoff, e_shnum, e_shstrndx };
}

function findSectionByName(elf, e_shoff, e_shnum, e_shstrndx, name) {
  // 在 SHT 中按名字找段 (只读预检). 返回段条目偏移, 未找到返回 -1.
  const name_len = name.length;
  const shstr_e = e_shoff + e_shstrndx * 64;
  const shstr_off = readU64(elf, shstr_e + 24);
  const shstr_sz = readU64(elf, shstr_e + 32);
  if (shstr_off > elf.length || shstr_sz > elf.length - shstr_off) {
    return -1;
  }
  for (let i = 0; i < e_shnum; i++) {
    const e = e_shoff + i * 64;
    const name_off = readU32(elf, e);
    if (name_off + name_len <= shstr_sz) {
      const start = shstr_off + name_off;
      if (elf.slice(start, start + name_len).equals(name)) {
        return e;
      }
    }
  }
  return -1;
}

function hasCodesignSection(elf) {
  try {
    const { e_shoff, e_shnum, e_shstrndx } = parseElfHeader(elf);
    return (
      findSectionByName(elf, e_shoff, e_shnum, e_shstrndx, CODESIGN_NAME) >= 0
    );
  } catch (e) {
    return false;
  }
}

function newShstrndx(old_shstrndx, cs_idx) {
  return cs_idx < old_shstrndx ? old_shstrndx - 1 : old_shstrndx;
}

function stripCodesign(buf) {
  // 剥离 .codesign 段. 返回 {removed, out}.
  const elf = Buffer.from(buf);
  const { e_shoff, e_shnum, e_shstrndx } = parseElfHeader(elf);

  const cs_entry_off = findSectionByName(
    elf,
    e_shoff,
    e_shnum,
    e_shstrndx,
    CODESIGN_NAME,
  );
  if (cs_entry_off < 0) {
    return { removed: false, out: elf };
  }
  const cs_idx = (cs_entry_off - e_shoff) / 64;

  const shstr_e = e_shoff + e_shstrndx * 64;
  const shstr_off = readU64(elf, shstr_e + 24);
  const shstr_sz = readU64(elf, shstr_e + 32);
  if (shstr_off > elf.length || shstr_sz > elf.length - shstr_off) {
    throw new Error("shstrtab out of bounds");
  }

  // 2. 新 shstrtab = 旧 shstrtab 删掉 ".codesign\0"
  const cs_name_off = readU32(elf, cs_entry_off);
  const cs_name_len = CODESIGN_NAME.length; // 10, 含 NUL
  const newShstr = Buffer.from(elf.slice(shstr_off, shstr_off + shstr_sz));
  let newShstrSz = newShstr.length;
  if (cs_name_off + cs_name_len <= newShstr.length) {
    newShstr.copyWithin(cs_name_off, cs_name_off + cs_name_len);
    newShstrSz = newShstr.length - cs_name_len;
  }
  const newShstrTrimmed = newShstr.slice(0, newShstrSz);

  // 3. 新 SHT = 旧 SHT 去掉 cs_idx 条目
  const newShnum = e_shnum - 1;
  const newSht = Buffer.alloc(newShnum * 64);
  let dst = 0;
  for (let i = 0; i < e_shnum; i++) {
    if (i === cs_idx) continue;
    const e = e_shoff + i * 64;
    elf.copy(newSht, dst, e, e + 64);
    dst += 64;
  }

  // 4. 截断到 .codesign 段文件偏移, 依次追加 新shstrtab / 8B对齐 新SHT
  const cs_sec_off = readU64(elf, cs_entry_off + 24);
  const keep_len = Math.min(cs_sec_off, elf.length);
  const new_shstr_off = keep_len;
  const new_sht_off = alignUp(new_shstr_off + newShstrSz, 8);
  const new_total = new_sht_off + newShnum * 64;

  const out = Buffer.alloc(new_total);
  elf.copy(out, 0, 0, keep_len);
  newShstrTrimmed.copy(out, new_shstr_off);
  newSht.copy(out, new_sht_off);

  // 5. 重写 shstrtab 条目
  const shstr_entry_off_in_new = newShstrndx(e_shstrndx, cs_idx) * 64;
  writeU64(out, new_sht_off + shstr_entry_off_in_new + 24, new_shstr_off);
  writeU64(out, new_sht_off + shstr_entry_off_in_new + 32, newShstrSz);

  // 6. 所有 sh_name > cs_name_off 的段名偏移整体前移 cs_name_len
  for (let i = 0; i < newShnum; i++) {
    const e = new_sht_off + i * 64;
    const noff = readU32(out, e);
    if (noff > cs_name_off) writeU32(out, e, noff - cs_name_len);
  }

  // 7. 更新 header
  writeU64(out, E_SHOFF, new_sht_off);
  writeU16(out, E_SHNUM, newShnum);
  if (cs_idx < e_shstrndx) writeU16(out, E_SHSTRNDX, e_shstrndx - 1);

  return { removed: true, out };
}

// ─────────────────── 签名必需的算法核心 ───────────────────
function injectCodesignSection(elf) {
  // 注入 4KB 占位 .codesign 段. 返回 {out, cs_off}.
  const { e_shoff, e_shnum, e_shstrndx } = parseElfHeader(elf);

  const shstr_e = e_shoff + e_shstrndx * 64;
  const shstr_off = readU64(elf, shstr_e + 24);
  const shstr_sz = readU64(elf, shstr_e + 32);
  if (shstr_off > elf.length || shstr_sz > elf.length - shstr_off) {
    throw new Error("shstrtab out of bounds");
  }

  // 1. cur_end: SHT 末尾与各段 off+sz 的最大值 (SHT_NOBITS=8 不占文件)
  let cur_end = e_shoff + e_shnum * 64;
  for (let i = 0; i < e_shnum; i++) {
    const e = e_shoff + i * 64;
    const sh_type = readU32(elf, e + 4);
    const off = readU64(elf, e + 24);
    const sz = sh_type === 8 ? 0 : readU64(elf, e + 32);
    if (off + sz > cur_end) cur_end = off + sz;
  }
  const cs_off = alignUp(cur_end, PAGE_SIZE);

  // 2. 新 shstrtab = 旧 + ".codesign\0"
  const newShstr = Buffer.concat([
    elf.slice(shstr_off, shstr_off + shstr_sz),
    CODESIGN_NAME,
  ]);
  const new_shstr_sz = newShstr.length;
  const cs_shname = shstr_sz; // .codesign 在新 shstrtab 内的偏移

  // 3. 新布局
  const new_shstr_off = cs_off + PAGE_SIZE;
  const new_sht_off = alignUp(new_shstr_off + new_shstr_sz, 8);
  const new_shnum = e_shnum + 1;
  const new_total = new_sht_off + new_shnum * 64;

  const buf = Buffer.alloc(new_total);
  // 4. 拷贝原内容: 只拷到 cs_off
  const copy_len = Math.min(elf.length, new_total, cs_off);
  elf.copy(buf, 0, 0, copy_len);

  newShstr.copy(buf, new_shstr_off);
  elf.copy(buf, new_sht_off, e_shoff, e_shoff + e_shnum * 64);

  // .codesign 段条目 (64B)
  const cs_e = new_sht_off + e_shnum * 64;
  writeU32(buf, cs_e + 0, cs_shname); // sh_name
  writeU32(buf, cs_e + 4, 1); // sh_type = SHT_PROGBITS
  writeU64(buf, cs_e + 24, cs_off); // sh_offset
  writeU64(buf, cs_e + 32, PAGE_SIZE); // sh_size
  writeU64(buf, cs_e + 48, PAGE_SIZE); // sh_addralign

  // 更新 shstrtab 条目偏移/大小
  const shstr_e_new = new_sht_off + e_shstrndx * 64;
  writeU64(buf, shstr_e_new + 24, new_shstr_off);
  writeU64(buf, shstr_e_new + 32, new_shstr_sz);

  // 更新 header: e_shoff / e_shnum; e_shstrndx 不变
  writeU64(buf, E_SHOFF, new_sht_off);
  writeU16(buf, E_SHNUM, new_shnum);

  return { out: buf, cs_off };
}

function merkleRootHash(data, cs_off, cs_len) {
  // fs-verity Merkle 树根哈希
  if (data.length === 0) {
    return sha256(Buffer.alloc(PAGE_SIZE));
  }

  const npages = Math.ceil(data.length / PAGE_SIZE);
  const cs_page_begin = Math.floor(cs_off / PAGE_SIZE);
  const cs_page_end = Math.ceil((cs_off + cs_len) / PAGE_SIZE);

  const hashes = [];
  for (let i = 0; i < npages; i++) {
    if (cs_len > 0 && cs_page_begin <= i && i < cs_page_end) {
      hashes.push(Buffer.alloc(HASH_OUT)); // 段所在页: 叶哈希置 0
      continue;
    }
    let page = data.slice(i * PAGE_SIZE, (i + 1) * PAGE_SIZE);
    if (page.length < PAGE_SIZE) {
      page = Buffer.concat([page, Buffer.alloc(PAGE_SIZE - page.length)]);
    }
    hashes.push(sha256(page));
  }

  if (npages === 1) {
    return Buffer.from(hashes[0]);
  }

  let cur = Buffer.concat(hashes);
  for (;;) {
    if (cur.length <= PAGE_SIZE) {
      const page = Buffer.concat([cur, Buffer.alloc(PAGE_SIZE - cur.length)]);
      return sha256(page);
    }
    const nxt = [];
    for (let i = 0; i < cur.length; i += PAGE_SIZE) {
      let page = cur.slice(i, i + PAGE_SIZE);
      if (page.length < PAGE_SIZE) {
        page = Buffer.concat([page, Buffer.alloc(PAGE_SIZE - page.length)]);
      }
      nxt.push(sha256(page));
    }
    cur = Buffer.concat(nxt);
  }
}

function buildDescriptor(sign_size, file_size, root, flags) {
  // 构造 256 字节 fs-verity descriptor
  const d = Buffer.alloc(DESC_SIZE);
  d[0] = 1; // version
  d[1] = 1; // hashAlgorithm = SHA-256
  d[2] = 12; // log2BlockSize = 2^12 = 4096
  d[3] = 0; // saltSize
  writeU32(d, 4, sign_size);
  writeU64(d, 8, file_size);
  root.copy(d, 16); // rootHash 左对齐填 64B, 后 32B 保持 0
  writeU32(d, 112, flags);
  d[255] = 3; // csVersion
  return d;
}

function signElf(elf, force) {
  // 签名主流程
  if (
    elf.length < 64 ||
    elf[0] !== 0x7f ||
    elf[1] !== 0x45 ||
    elf[2] !== 0x4c ||
    elf[3] !== 0x46 ||
    elf[4] !== 2
  ) {
    throw new Error("not ELF64");
  }

  let buf = Buffer.from(elf);
  if (hasCodesignSection(buf)) {
    if (!force) {
      throw new Error(
        "already has a .codesign section; strip first or use --force",
      );
    }
    buf = stripCodesign(buf).out;
  }

  // 1. 注入 4KB 占位 .codesign 段
  const { out: tmp0, cs_off } = injectCodesignSection(buf);
  const file_size = tmp0.length;

  // 2. merkle 根哈希
  const root = merkleRootHash(tmp0, cs_off, PAGE_SIZE);

  // 3/4. descriptor(signSize=0) 用于摘要
  const desc_for_digest = buildDescriptor(0, file_size, root, FLAG_SELF_SIGN);
  // 5. signature = SHA256(descriptor)
  const signature = sha256(desc_for_digest);
  // 6. descriptor(signSize=32) 用于落盘
  const desc_on_disk = buildDescriptor(32, file_size, root, FLAG_SELF_SIGN);

  // 7. ElfSignInfo: 8B 头 + descriptor 256B + signature 32B = 296B
  const payload = Buffer.alloc(4 + 4 + DESC_SIZE + HASH_OUT);
  writeU32(payload, 0, FS_VERITY_DESCRIPTOR_TYPE); // type
  writeU32(payload, 4, DESC_SIZE + HASH_OUT); // length = 288
  desc_on_disk.copy(payload, 8);
  signature.copy(payload, 8 + DESC_SIZE);

  // 8. 原地写入段内
  payload.copy(tmp0, cs_off);
  return tmp0;
}

// ─────────────────── 文件 I/O 层 ───────────────────
function signFileAtomic(path, force) {
  const raw = fs.readFileSync(path);
  const signed = signElf(raw, force);

  let mode = null;
  try {
    mode = fs.statSync(path).mode & 0o7777;
  } catch (e) {
    // ignore
  }

  const tmp_path = `${path}.ohos-signing.${process.pid}.tmp`;
  try {
    fs.unlinkSync(tmp_path);
  } catch (e) {
    /* ignore */
  }
  fs.writeFileSync(tmp_path, signed);
  if (mode !== null) fs.chmodSync(tmp_path, mode);
  fs.renameSync(tmp_path, path);
}

function main() {
  let force = false;
  let strip_only = false;
  const positional = [];
  for (const a of process.argv.slice(2)) {
    if (a === "--force" || a === "-f") force = true;
    else if (a === "--strip") strip_only = true;
    else positional.push(a);
  }
  if (positional.length < 1 || positional.length > 2) {
    process.stderr.write(
      `usage: ${process.argv[1]} <input_elf> [output_elf] [--force] [--strip]\n` +
        "  (output defaults to input, in-place)\n",
    );
    return 1;
  }
  const in_path = positional[0];
  const out_path = positional.length === 2 ? positional[1] : in_path;

  try {
    if (strip_only) {
      const raw = fs.readFileSync(in_path);
      const { removed, out } = stripCodesign(Buffer.from(raw));
      if (!removed) {
        console.log(`no .codesign section to strip: ${in_path}`);
        return 0;
      }
      fs.writeFileSync(out_path, out);
      console.log(`strip ok: ${in_path} → ${out_path} (${out.length} bytes)`);
      return 0;
    }

    if (in_path === out_path) {
      signFileAtomic(in_path, force);
      console.log(
        `selfsign ok: ${in_path} (in-place, ${force ? "force" : "append-only"})`,
      );
    } else {
      const raw = fs.readFileSync(in_path);
      const signed = signElf(raw, force);
      fs.writeFileSync(out_path, signed);
      console.log(
        `selfsign ok: ${in_path} → ${out_path} (${signed.length} bytes)`,
      );
    }
  } catch (e) {
    process.stderr.write(`error: ${e.message}\n`);
    return 2;
  }
  return 0;
}

// 作为库被 require 时不自动执行 main；
// 仅在直接 `node selfsign.js` 时跑命令行入口。
if (require.main === module) {
  process.exit(main());
}

// ─────────────────── 库导出 ───────────────────
// 导出这些函数，使本文件既可作为命令行工具直接运行，
// 也可作为模块被其他脚本 require 引用。
module.exports = {
  // 高层 API
  signElf,           // (elf: Buffer, force?: boolean) => Buffer
  signFileAtomic,    // (path: string, force?: boolean) => void  原子原地签名
  // 段操作
  stripCodesign,     // (buf: Buffer) => { removed: boolean, out: Buffer }
  hasCodesignSection,// (elf: Buffer) => boolean
  injectCodesignSection, // (elf: Buffer) => { out: Buffer, cs_off: number }
  // 算法核心（导出便于复用/测试）
  merkleRootHash,
  buildDescriptor,
  parseElfHeader,
  findSectionByName,
};
