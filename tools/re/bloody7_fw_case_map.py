#!/usr/bin/env python3
"""
Extract partial product-code -> firmware-template mappings from Bloody7.exe.

This script decodes known jump tables inside the legacy USB firmware template
selection switch and resolves each case target to the pushed UTF-16 template
string (for example: A60cir_P3332A_%.3X_%d).
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

import lief
from capstone import CS_ARCH_X86, CS_MODE_32, Cs


DEFAULT_EXE = (
    "tmp/re/bloody7_rar/Bloody7_V2025.1222_MUI.exe/"
    "program files/Bloody7/Bloody7.exe"
)


def parse_hex(value: str) -> int:
    return int(value, 0)


def va_to_file_offset(binary: lief.PE.Binary, va: int) -> int | None:
    imagebase = binary.optional_header.imagebase
    rva = va - imagebase
    for section in binary.sections:
        start = section.virtual_address
        end = start + max(section.virtual_size, section.size)
        if start <= rva < end:
            return section.offset + (rva - start)
    return None


def read_u32(text_bytes: bytes, text_va: int, va: int) -> int:
    offset = va - text_va
    return struct.unpack_from("<I", text_bytes, offset)[0]


def decode_utf16_ascii_at_va(binary: lief.PE.Binary, raw: bytes, va: int) -> str | None:
    file_offset = va_to_file_offset(binary, va)
    if file_offset is None or file_offset < 0 or file_offset >= len(raw):
        return None

    chars: list[str] = []
    cursor = file_offset
    for _ in range(256):
        if cursor + 1 >= len(raw):
            break
        ch = raw[cursor]
        z = raw[cursor + 1]
        if ch == 0 and z == 0:
            break
        if z != 0 or ch < 0x20 or ch > 0x7E:
            return None
        chars.append(chr(ch))
        cursor += 2

    decoded = "".join(chars)
    return decoded if len(decoded) >= 3 else None


def extract_case_template(binary: lief.PE.Binary, text_bytes: bytes, text_va: int, raw: bytes, target_va: int) -> str | None:
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    start = target_va
    end = target_va + 0x80
    code = text_bytes[start - text_va : end - text_va]
    for insn in md.disasm(code, start):
        if insn.mnemonic == "push" and insn.operands and insn.operands[0].type == 2:
            candidate_va = insn.operands[0].imm & 0xFFFFFFFF
            decoded = decode_utf16_ascii_at_va(binary, raw, candidate_va)
            if decoded is not None:
                return decoded
        if insn.mnemonic == "jmp" and "0x41c014" in insn.op_str:
            break
    return None


def table_rows(
    binary: lief.PE.Binary,
    raw: bytes,
    text_bytes: bytes,
    text_va: int,
    table_name: str,
    table_base: int,
    case_start: int,
    case_count: int,
    default_target: int,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for index in range(case_count):
        case_code = case_start + index
        target = read_u32(text_bytes, text_va, table_base + (index * 4))
        template = None
        if target != default_target:
            template = extract_case_template(binary, text_bytes, text_va, raw, target)
        rows.append(
            {
                "table": table_name,
                "case_code": case_code,
                "case_hex": f"0x{case_code:03x}",
                "target": f"0x{target:08x}",
                "is_default": target == default_target,
                "firmware_template": template,
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract Bloody7 firmware switch-case mapping.")
    parser.add_argument("--exe", default=DEFAULT_EXE, help="Path to Bloody7.exe")
    parser.add_argument("--json-out", default="", help="Optional JSON output path")
    parser.add_argument("--table-4b8-base", type=parse_hex, default=0x41AAA7)
    parser.add_argument("--table-4e0-base", type=parse_hex, default=0x41AB1D)
    parser.add_argument("--default-target", type=parse_hex, default=0x41BF75)
    args = parser.parse_args()

    exe_path = Path(args.exe)
    if not exe_path.exists():
        raise FileNotFoundError(f"Missing executable: {exe_path}")

    binary = lief.parse(str(exe_path))
    raw = exe_path.read_bytes()
    text = next((section for section in binary.sections if section.name == ".text"), None)
    if text is None:
        raise RuntimeError("Could not find .text section.")
    imagebase = binary.optional_header.imagebase
    text_va = imagebase + text.virtual_address
    text_bytes = bytes(text.content)

    rows = []
    rows.extend(
        table_rows(
            binary=binary,
            raw=raw,
            text_bytes=text_bytes,
            text_va=text_va,
            table_name="table_4b8",
            table_base=args.table_4b8_base,
            case_start=0x4B8,
            case_count=0x15,
            default_target=args.default_target,
        )
    )
    rows.extend(
        table_rows(
            binary=binary,
            raw=raw,
            text_bytes=text_bytes,
            text_va=text_va,
            table_name="table_4e0",
            table_base=args.table_4e0_base,
            case_start=0x4E0,
            case_count=0x15,
            default_target=args.default_target,
        )
    )

    mapped = [row for row in rows if row["firmware_template"] is not None]
    print(f"mapped_cases={len(mapped)} total_rows={len(rows)}")
    for row in mapped:
        print(
            f"{row['table']} {row['case_hex']} -> {row['firmware_template']} (target={row['target']})"
        )

    t50_cases = [row for row in mapped if str(row["firmware_template"]).startswith("A60cir_")]
    if t50_cases:
        print("")
        print("T50-family cases:")
        for row in t50_cases:
            print(f"  {row['table']} {row['case_hex']} -> {row['firmware_template']}")

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "exe": str(exe_path),
            "tables": {
                "table_4b8": hex(args.table_4b8_base),
                "table_4e0": hex(args.table_4e0_base),
                "default_target": hex(args.default_target),
            },
            "rows": rows,
            "mapped_rows": mapped,
            "t50_cases": t50_cases,
        }
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nwrote {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
