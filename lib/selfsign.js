#!/usr/bin/env node
// Copyright (C) 2026 hqzing
// SPDX-License-Identifier: 0BSD
// Repository: https://github.com/hqzing/ohos-selfsign
//
// Licensed under the BSD Zero Clause License.

/*
 * selfsign.js — 轻量级 OpenHarmony 二进制自签名工具
 *
 * 用法:
 *     node selfsign.js <input_elf> [output_elf] [--force] [--strip] [--check]
 *         缺省 output 时, inplace 改写 input.
 *         --force : 若已含 .codesign 段, 先剥离再重签
 *         --strip : 仅剥离 .codesign 段, 不做签名
 *         --check : 只读校验已有自签名的有效性, 不写任何文件
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
  // 校验并解析 ELF64 header (只读预检).
  // ELF64 允许段表条目大于 64 字节 (携带扩展字段), 故只拒绝小于 64 的;
  // 实际条目大小随返回值传出, 后续所有 SHT 遍历/越界校验均按它步进.
  // 返回 {e_shoff, e_shentsize, e_shnum, e_shstrndx}
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
    e_shentsize < 64 ||
    e_shoff === 0 ||
    e_shnum === 0 ||
    e_shstrndx >= e_shnum
  ) {
    throw new Error("ELF has no usable section header table");
  }
  if (
    e_shoff > elf.length ||
    e_shnum > Math.floor((elf.length - e_shoff) / e_shentsize)
  ) {
    throw new Error("section header table out of bounds");
  }
  return { e_shoff, e_shentsize, e_shnum, e_shstrndx };
}

function findSectionByName(elf, e_shoff, e_shentsize, e_shnum, e_shstrndx, name) {
  // 在 SHT 中按名字找段 (只读预检). 段条目按实际 e_shentsize 步进.
  // 返回段条目偏移, 未找到返回 -1.
  const name_len = name.length;
  const shstr_e = e_shoff + e_shstrndx * e_shentsize;
  const shstr_off = readU64(elf, shstr_e + 24);
  const shstr_sz = readU64(elf, shstr_e + 32);
  if (shstr_off > elf.length || shstr_sz > elf.length - shstr_off) {
    return -1;
  }
  for (let i = 0; i < e_shnum; i++) {
    const e = e_shoff + i * e_shentsize;
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
    const { e_shoff, e_shentsize, e_shnum, e_shstrndx } = parseElfHeader(elf);
    return (
      findSectionByName(
        elf,
        e_shoff,
        e_shentsize,
        e_shnum,
        e_shstrndx,
        CODESIGN_NAME,
      ) >= 0
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
  const { e_shoff, e_shentsize, e_shnum, e_shstrndx } = parseElfHeader(elf);

  const cs_entry_off = findSectionByName(
    elf,
    e_shoff,
    e_shentsize,
    e_shnum,
    e_shstrndx,
    CODESIGN_NAME,
  );
  if (cs_entry_off < 0) {
    return { removed: false, out: elf };
  }
  const cs_idx = (cs_entry_off - e_shoff) / e_shentsize;

  const shstr_e = e_shoff + e_shstrndx * e_shentsize;
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

  // 3. 新 SHT = 旧 SHT 去掉 cs_idx 条目 (条目不压缩, 按原 e_shentsize 保留)
  const newShnum = e_shnum - 1;
  const newSht = Buffer.alloc(newShnum * e_shentsize);
  let dst = 0;
  for (let i = 0; i < e_shnum; i++) {
    if (i === cs_idx) continue;
    const e = e_shoff + i * e_shentsize;
    elf.copy(newSht, dst, e, e + e_shentsize);
    dst += e_shentsize;
  }

  // 4. 新表落位: 若 .codesign 段数据之后恰好只有旧 shstrtab 与旧 SHT
  //    (即本工具自己签出的布局), 照旧截断到段偏移并在原位重建, 文件不膨胀;
  //    否则 (如签名后又被 patchelf 等工具重排过, 段数据之后仍有活跃内容,
  //    例如被挪到文件尾部新增段的 .interp) 不截断, 新表追加到文件末尾,
  //    原段数据成为无引用的死字节.
  const cs_sec_off = readU64(elf, cs_entry_off + 24);
  const compact =
    cs_sec_off <= elf.length &&
    cs_sec_off + PAGE_SIZE === shstr_off &&
    e_shoff === alignUp(shstr_off + shstr_sz, 8) &&
    elf.length === e_shoff + e_shnum * e_shentsize;
  const keep_len = compact ? cs_sec_off : elf.length;
  const new_shstr_off = keep_len;
  const new_sht_off = alignUp(new_shstr_off + newShstrSz, 8);
  const new_total = new_sht_off + newShnum * e_shentsize;

  const out = Buffer.alloc(new_total);
  elf.copy(out, 0, 0, keep_len);
  newShstrTrimmed.copy(out, new_shstr_off);
  newSht.copy(out, new_sht_off);

  // 5. 重写 shstrtab 条目
  const shstr_entry_off_in_new = newShstrndx(e_shstrndx, cs_idx) * e_shentsize;
  writeU64(out, new_sht_off + shstr_entry_off_in_new + 24, new_shstr_off);
  writeU64(out, new_sht_off + shstr_entry_off_in_new + 32, newShstrSz);

  // 6. 所有 sh_name > cs_name_off 的段名偏移整体前移 cs_name_len
  for (let i = 0; i < newShnum; i++) {
    const e = new_sht_off + i * e_shentsize;
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
  const { e_shoff, e_shentsize, e_shnum, e_shstrndx } = parseElfHeader(elf);

  const shstr_e = e_shoff + e_shstrndx * e_shentsize;
  const shstr_off = readU64(elf, shstr_e + 24);
  const shstr_sz = readU64(elf, shstr_e + 32);
  if (shstr_off > elf.length || shstr_sz > elf.length - shstr_off) {
    throw new Error("shstrtab out of bounds");
  }

  // 1. cur_end: SHT 末尾与各段 off+sz 的最大值 (SHT_NOBITS=8 不占文件),
  // 且不小于文件实际长度 (段表之后可能拖着附加数据)
  let cur_end = e_shoff + e_shnum * e_shentsize;
  for (let i = 0; i < e_shnum; i++) {
    const e = e_shoff + i * e_shentsize;
    const sh_type = readU32(elf, e + 4);
    const off = readU64(elf, e + 24);
    const sz = sh_type === 8 ? 0 : readU64(elf, e + 32);
    if (off + sz > cur_end) cur_end = off + sz;
  }
  if (elf.length > cur_end) cur_end = elf.length;
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
  const new_total = new_sht_off + new_shnum * e_shentsize;

  const buf = Buffer.alloc(new_total);
  // 4. 拷贝原内容: 只拷到 cs_off
  const copy_len = Math.min(elf.length, new_total, cs_off);
  elf.copy(buf, 0, 0, copy_len);

  newShstr.copy(buf, new_shstr_off);
  elf.copy(buf, new_sht_off, e_shoff, e_shoff + e_shnum * e_shentsize);

  // .codesign 段条目 (前 64B 为标准字段, 超出 64B 的扩展部分保持 0)
  const cs_e = new_sht_off + e_shnum * e_shentsize;
  writeU32(buf, cs_e + 0, cs_shname); // sh_name
  writeU32(buf, cs_e + 4, 1); // sh_type = SHT_PROGBITS
  writeU64(buf, cs_e + 24, cs_off); // sh_offset
  writeU64(buf, cs_e + 32, PAGE_SIZE); // sh_size
  writeU64(buf, cs_e + 48, PAGE_SIZE); // sh_addralign

  // 更新 shstrtab 条目偏移/大小
  const shstr_e_new = new_sht_off + e_shstrndx * e_shentsize;
  writeU64(buf, shstr_e_new + 24, new_shstr_off);
  writeU64(buf, shstr_e_new + 32, new_shstr_sz);

  // 更新 header: e_shoff / e_shnum; e_shstrndx 不变
  writeU64(buf, E_SHOFF, new_sht_off);
  writeU16(buf, E_SHNUM, new_shnum);

  return { out: buf, cs_off };
}

function merkleRootHash(data, cs_off, cs_len) {
  // fs-verity Merkle 树根哈希 + 中间层哈希.
  // 返回 { root, mid }; mid = 叶层与根所在层之间的所有层, 从低往高逐层
  // 把 32B 哈希按顺序拼接 (叶层 <= 4096B 时不存在中间层), 签名时写入
  // .codesign 段内 payload 之后.
  if (data.length === 0) {
    return { root: sha256(Buffer.alloc(PAGE_SIZE)), mid: Buffer.alloc(0) };
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
    return { root: Buffer.from(hashes[0]), mid: Buffer.alloc(0) };
  }

  let cur = Buffer.concat(hashes);
  const mid = []; // 中间层暂存: 低于根所在层的各层, 从低往高拼接
  while (cur.length > PAGE_SIZE) {
    const nxt = [];
    for (let i = 0; i < cur.length; i += PAGE_SIZE) {
      let page = cur.slice(i, i + PAGE_SIZE);
      if (page.length < PAGE_SIZE) {
        page = Buffer.concat([page, Buffer.alloc(PAGE_SIZE - page.length)]);
      }
      nxt.push(sha256(page));
    }
    cur = Buffer.concat(nxt);
    if (cur.length > PAGE_SIZE) {
      mid.push(cur); // 根所在层 (packed <= 4096) 不属于中间层
    }
  }
  const page = Buffer.concat([cur, Buffer.alloc(PAGE_SIZE - cur.length)]);
  return { root: sha256(page), mid: Buffer.concat(mid) };
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

  // 2. merkle 根哈希; mid 为中间层哈希
  const { root, mid } = merkleRootHash(tmp0, cs_off, PAGE_SIZE);

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

  // 8. 原地写入段内: payload 之后紧跟中间层哈希, 可用容量
  // 4096-296=3800B, 中间层更长时保留靠叶层一侧的前 3800B
  payload.copy(tmp0, cs_off);
  mid.copy(tmp0, cs_off + payload.length, 0, PAGE_SIZE - payload.length);
  return tmp0;
}

// ─────────────────── 只读校验 (--check) ───────────────────
function checkSelfsign(elf) {
  // 只读校验已有自签名的有效性 (--check 的实现).
  // 校验项 (全部通过才算有效; 多项不符时按序报告第一个):
  //   1. 可解析的 ELF64 (走 parseElfHeader 的全部检查), 存在 .codesign 段,
  //      且段内 ElfSignInfo 头 type=1 / length=288
  //   2. descriptor 固定字段: version=1, hashAlgorithm=1, log2BlockSize=12,
  //      csVersion=3
  //   3. signSize=32 且 fileSize=文件实际大小
  //   4. 存储的 merkle 根哈希 == 对整个文件重算的根
  //   5. 存储的 signature == SHA256(signSize 置 0 后的 descriptor)
  // 明确不校验 merkle 中间层 (payload 296B 之后的区域): .codesign 段覆盖
  // 的页在 merkle 叶层本来就置 0, 篡改中间层不影响根, 此类篡改下本校验
  // 仍通过 (预期行为).
  // 返回 { ok, reason }; ok 为 false 时 reason 为原因串 (文案五个实现统一).

  // 1a. ELF64 预检 (parse 失败含段表不可用)
  let hdr;
  try {
    hdr = parseElfHeader(elf);
  } catch (e) {
    return { ok: false, reason: "not ELF64" };
  }

  // 1b. 定位 .codesign 段, 段内至少要容得下 296B payload
  const cs_entry_off = findSectionByName(
    elf,
    hdr.e_shoff,
    hdr.e_shentsize,
    hdr.e_shnum,
    hdr.e_shstrndx,
    CODESIGN_NAME,
  );
  if (cs_entry_off < 0) {
    return { ok: false, reason: "no .codesign section" };
  }
  const cs_off = readU64(elf, cs_entry_off + 24);
  const cs_size = readU64(elf, cs_entry_off + 32);
  const payload_len = 8 + DESC_SIZE + HASH_OUT;
  if (cs_size < payload_len || cs_off + payload_len > elf.length) {
    return { ok: false, reason: "bad ElfSignInfo header" };
  }

  // 1c. ElfSignInfo 头: type=1, length=288
  if (
    readU32(elf, cs_off) !== FS_VERITY_DESCRIPTOR_TYPE ||
    readU32(elf, cs_off + 4) !== DESC_SIZE + HASH_OUT
  ) {
    return { ok: false, reason: "bad ElfSignInfo header" };
  }

  const desc = elf.slice(cs_off + 8, cs_off + 8 + DESC_SIZE);
  const sig = elf.slice(cs_off + 8 + DESC_SIZE, cs_off + payload_len);

  // 2. descriptor 固定字段: version/hashAlgorithm/log2BlockSize/csVersion
  if (desc[0] !== 1 || desc[1] !== 1 || desc[2] !== 12 || desc[255] !== 3) {
    return { ok: false, reason: "unsupported descriptor fields" };
  }

  // 3. signSize=32 且 fileSize=文件实际大小
  if (readU32(desc, 4) !== HASH_OUT) {
    return { ok: false, reason: "signSize mismatch" };
  }
  if (readU64(desc, 8) !== elf.length) {
    return { ok: false, reason: "fileSize mismatch" };
  }

  // 4. merkle 根哈希: 重算整个文件的根 (中间层忽略)
  const { root } = merkleRootHash(elf, cs_off, PAGE_SIZE);
  if (!desc.slice(16, 16 + HASH_OUT).equals(root)) {
    return { ok: false, reason: "merkle root mismatch" };
  }

  // 5. signature == SHA256(signSize 置 0 后的 descriptor)
  const desc0 = Buffer.from(desc);
  desc0.fill(0, 4, 8);
  if (!sig.equals(sha256(desc0))) {
    return { ok: false, reason: "signature mismatch" };
  }

  return { ok: true, reason: null };
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
  let check_only = false;
  const positional = [];
  for (const a of process.argv.slice(2)) {
    if (a === "--force" || a === "-f") force = true;
    else if (a === "--strip") strip_only = true;
    else if (a === "--check") check_only = true;
    else positional.push(a);
  }
  // --check 与输出路径/--force/--strip 组合属用法错误
  if (
    positional.length < 1 ||
    positional.length > 2 ||
    (check_only && (force || strip_only || positional.length === 2))
  ) {
    process.stderr.write(
      `usage: ${process.argv[1]} <input_elf> [output_elf] [--force] [--strip] [--check]\n` +
        "  (output defaults to input, in-place)\n",
    );
    return 1;
  }
  const in_path = positional[0];
  const out_path = positional.length === 2 ? positional[1] : in_path;

  try {
    if (check_only) {
      // --check: 只读校验, 不写任何文件
      const raw = fs.readFileSync(in_path);
      const { ok, reason } = checkSelfsign(raw);
      if (ok) {
        console.log(`check ok: ${in_path}`);
        return 0;
      }
      process.stderr.write(`check failed: ${in_path} (${reason})\n`);
      return 1;
    }

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
  checkSelfsign,     // (elf: Buffer) => { ok: boolean, reason: string|null }  只读校验自签名
  // 算法核心（导出便于复用/测试）
  merkleRootHash,
  buildDescriptor,
  parseElfHeader,
  findSectionByName,
};
