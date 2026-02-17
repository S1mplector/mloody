#!/usr/bin/env python3
"""
Static opcode map extractor for Bloody7.exe (v2025.1222-style builds).

This script focuses on the HID packet construction layer:
  - fixed 14-byte-argument packet builder
  - variable-payload packet builder
  - fixed packet builder with readback verification
  - transport exchange / readback routines

The default builder/transport addresses are version-specific VMAs from
Bloody7_V2025.1222_MUI. Use --builder-* / --transport-* to override when needed.
"""

from __future__ import annotations

import argparse
import bisect
import json
import struct
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import lief
from capstone import CS_ARCH_X86, CS_MODE_32, Cs


DEFAULT_EXE = (
    "tmp/re/bloody7_rar/Bloody7_V2025.1222_MUI.exe/"
    "program files/Bloody7/Bloody7.exe"
)


def parse_hex_vma(value: str) -> int:
    return int(value, 0)


def find_text_section(binary: lief.PE.Binary) -> lief.PE.Section:
    for section in binary.sections:
        if section.name == ".text":
            return section
    raise RuntimeError("Could not find .text section.")


def find_rel32_calls(text_bytes: bytes, text_vma: int, target_vma: int) -> list[int]:
    hits: list[int] = []
    for offset in range(len(text_bytes) - 5):
        if text_bytes[offset] != 0xE8:
            continue
        rel = struct.unpack_from("<i", text_bytes, offset + 1)[0]
        callsite = text_vma + offset
        target = (callsite + 5 + rel) & 0xFFFFFFFF
        if target == target_vma:
            hits.append(callsite)
    return hits


def find_nearest_prologue(text_bytes: bytes, text_vma: int, callsite_vma: int) -> int | None:
    search_start = max(text_vma, callsite_vma - 0x600)
    for vma in range(callsite_vma - 3, search_start - 1, -1):
        offset = vma - text_vma
        if text_bytes[offset : offset + 3] == b"\x55\x8b\xec":
            return vma
    return None


def disassemble_range(text_bytes: bytes, text_vma: int, start_vma: int, end_vma: int) -> list[Any]:
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False
    start_offset = start_vma - text_vma
    end_offset = end_vma - text_vma
    return list(md.disasm(text_bytes[start_offset:end_offset], start_vma))


def owner_lookup(binary: lief.PE.Binary, address_vma: int) -> tuple[str | None, int | None]:
    exports: list[tuple[int, str]] = []
    imagebase = binary.optional_header.imagebase
    for func in binary.exported_functions:
        if not func.name:
            continue
        exports.append((imagebase + func.address, func.name))
    exports.sort()
    if not exports:
        return None, None
    addrs = [addr for addr, _ in exports]
    index = bisect.bisect_right(addrs, address_vma) - 1
    if index < 0:
        return None, None
    return exports[index][1], exports[index][0]


def extract_context_features(insns: list[Any]) -> dict[str, Any]:
    cl_value = None
    dl_value = None
    pushes: list[str] = []
    immed_push_values: list[int] = []
    cl_index = None

    for idx, insn in enumerate(insns):
        if insn.mnemonic == "mov" and insn.op_str.startswith("cl, "):
            try:
                cl_value = int(insn.op_str.split(",", 1)[1].strip(), 0)
                cl_index = idx
            except ValueError:
                pass
        if insn.mnemonic == "mov" and insn.op_str.startswith("dl, "):
            try:
                dl_value = int(insn.op_str.split(",", 1)[1].strip(), 0)
            except ValueError:
                pass
        if insn.mnemonic == "push":
            pushes.append(insn.op_str)
            try:
                immed_push_values.append(int(insn.op_str, 0))
            except ValueError:
                pass

    var_len_guess = None
    if cl_index is not None:
        for back in range(cl_index - 1, -1, -1):
            insn = insns[back]
            if insn.mnemonic != "push":
                continue
            try:
                var_len_guess = int(insn.op_str, 0)
                break
            except ValueError:
                continue

    return {
        "cl": cl_value,
        "dl": dl_value,
        "pushes": pushes,
        "immediate_push_values": immed_push_values,
        "var_length_guess": var_len_guess,
    }


def build_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    by_owner: dict[str, Counter] = defaultdict(Counter)
    by_builder = Counter()
    by_opcode = Counter()

    for row in rows:
        builder = row["kind"]
        owner = row["owner_name"] or "unknown_owner"
        opcode = row["cl"]
        by_builder[builder] += 1
        if opcode is not None:
            by_opcode[(builder, opcode)] += 1
        by_owner[owner][(builder, opcode, row["dl"])] += 1

    summary["by_builder"] = dict(by_builder)
    summary["by_opcode"] = {
        f"{builder}:0x{opcode:02x}" if opcode is not None else f"{builder}:unknown": count
        for (builder, opcode), count in sorted(by_opcode.items(), key=lambda item: (-item[1], item[0]))
    }
    summary["by_owner"] = {}
    for owner, counter in sorted(by_owner.items()):
        summary["by_owner"][owner] = {
            f"{builder}/cl={('0x%02x' % cl) if cl is not None else 'unknown'}/dl={('0x%02x' % dl) if dl is not None else 'unknown'}": count
            for (builder, cl, dl), count in sorted(
                counter.items(),
                key=lambda item: (
                    -item[1],
                    item[0][0],
                    -1 if item[0][1] is None else item[0][1],
                    -1 if item[0][2] is None else item[0][2],
                ),
            )
        }
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract static HID opcode map from Bloody7.exe.")
    parser.add_argument("--exe", default=DEFAULT_EXE, help="Path to Bloody7.exe")
    parser.add_argument("--builder-fixed", default="0x55adcc", type=parse_hex_vma)
    parser.add_argument("--builder-var", default="0x55aea4", type=parse_hex_vma)
    parser.add_argument("--builder-verify", default="0x55af60", type=parse_hex_vma)
    parser.add_argument("--transport-exchange", default="0x1333c90", type=parse_hex_vma)
    parser.add_argument("--transport-readback", default="0x1333df8", type=parse_hex_vma)
    parser.add_argument("--json-out", default="", help="Optional path to write JSON output")
    args = parser.parse_args()

    exe_path = Path(args.exe)
    if not exe_path.exists():
        raise FileNotFoundError(f"Missing executable: {exe_path}")

    binary = lief.parse(str(exe_path))
    text = find_text_section(binary)
    imagebase = binary.optional_header.imagebase
    text_vma = imagebase + text.virtual_address
    text_bytes = bytes(text.content)

    targets = {
        args.builder_fixed: "builder_fixed",
        args.builder_var: "builder_var",
        args.builder_verify: "builder_verify",
        args.transport_exchange: "transport_exchange",
        args.transport_readback: "transport_readback",
    }

    rows: list[dict[str, Any]] = []
    for target_vma, kind in targets.items():
        for callsite_vma in find_rel32_calls(text_bytes, text_vma, target_vma):
            prologue_vma = find_nearest_prologue(text_bytes, text_vma, callsite_vma)
            if prologue_vma is None:
                continue
            insns = disassemble_range(text_bytes, text_vma, prologue_vma, callsite_vma + 5)
            if not insns:
                continue
            if insns[-1].address != callsite_vma or insns[-1].mnemonic != "call":
                continue
            context = insns[-30:]
            features = extract_context_features(context)
            owner_name, owner_addr = owner_lookup(binary, callsite_vma)
            rows.append(
                {
                    "site": f"0x{callsite_vma:08x}",
                    "kind": kind,
                    "target": f"0x{target_vma:08x}",
                    "owner_name": owner_name,
                    "owner_address": f"0x{owner_addr:08x}" if owner_addr is not None else None,
                    "cl": features["cl"],
                    "dl": features["dl"],
                    "var_length_guess": features["var_length_guess"],
                    "pushes_tail": features["pushes"][-16:],
                    "context_tail": [
                        {
                            "address": f"0x{insn.address:08x}",
                            "mnemonic": insn.mnemonic,
                            "op_str": insn.op_str,
                        }
                        for insn in context[-16:]
                    ],
                }
            )

    rows.sort(key=lambda item: int(item["site"], 16))
    result = {
        "exe": str(exe_path),
        "imagebase": f"0x{imagebase:08x}",
        "text_vma": f"0x{text_vma:08x}",
        "targets": {name: f"0x{value:08x}" for value, name in targets.items()},
        "row_count": len(rows),
        "rows": rows,
        "summary": build_summary(rows),
    }

    print(json.dumps(result["summary"], indent=2))
    print(f"rows={result['row_count']}")

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"wrote {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
