# Bloody7 T50 Reverse-Engineering Notes

This document tracks high-confidence findings from the extracted Bloody7 bundle and USB capture artifacts under `tmp/`.

## Extracted App Clues

- Region key maps for Series T (`Data/Mouse/Forms/KeySet/English/Region_kernel{1..4}_SeriesT.txt`) decode to the same key index layout across kernels.
- `Key9 (1)` maps to `KeyCodeIndex=7` and `Key10 (N)` maps to `KeyCodeIndex=8`, matching the top CPI rocker behavior observed on T50.
- Default kernel XMLs show kernel-dependent simulator assignments for CPI controls:
  - `kernel1` / `kernel4`: CPI controls use simulator family `15`.
  - `kernel2` / `kernel3`: CPI controls use simulator family `26` (and related `27` entries).
- `Bloody7_English.ini` strings include multiple "stored in mouse memory" apply notices, implying per-page apply/commit transactions rather than a single global save flag.
- Static disassembly confirms three packet constructors in `Bloody7.exe`:
  - fixed packet builder (`0x55adcc`): fills bytes `2..15`
  - variable packet builder (`0x55aea4`): fills bytes `2..7` and copies variable payload into bytes `8+`
  - fixed+readback verifier (`0x55af60`): same fixed frame with post-write readback validation
- `Hid_simulator` includes split-channel color writes with subcommands `06 07`, `06 08`, `06 09`, `06 0A`, `06 0B`, `06 0C`; each transmits 58 channel bytes as:
  - packet bytes `6..7` = chunk bytes `56..57`
  - packet bytes `8..63` = chunk bytes `0..55`
- Static disassembly of `Hid_sled` (`0x55f4f8`/`0x55f578`) shows dedicated SLED/profile probes:
  - `opcode 0x15` with a single parameter byte written at payload offset `8`
  - `opcode 0x16` with a boolean parameter byte written at payload offset `8` (`0` or `1`)

## Captured Persistence Transaction (Windows)

From `tmp/captures/09DA_79EF_Capture.pcapng` frame comments and `usb.data_fragment` payloads:

1. Warmup:
   - `07 03 06 05`
   - `07 03 06 06`
   - `07 03 06 02`
2. Open brightness menu:
   - `07 03 03 0B ... 01 ...`
3. Brightness ramp + ticks:
   - `07 11 ... 00` + `07 0A`
   - `07 11 ... 01` + `07 0A`
   - `07 11 ... 02` + `07 0A`
   - `07 11 ... 03` + `07 0A`
4. Press OK:
   - `07 03 03 0B ... 00 ...`
5. Save tail:
   - `07 14`
   - `07 05`
   - `07 2F ... 02 ... E2 ...`
   - `07 0E`
   - `07 0F ... 07 ...`
   - `07 0C ... 06 80 01 ...`
   - `07 0A`
6. Finalize:
   - `07 03 06 05`
   - `07 03 06 06`

This exact flow is now available as CLI strategy `capture-v3` via:

```bash
./build/mloody t50 save --strategy capture-v3
```

## Current Working Hypothesis

- `capture-v2` is a partial tail replay and may be insufficient for reliable on-device persistence by itself.
- `capture-v3` better mirrors GUI behavior and should be the default persistence probe while we map DPI/core writes.
- `capture-v4` (`capture-v3` + `Hid_major` sync tail `07`, `08`, `06`, `1e 01`, `0a`) is now implemented for additional commit probing.
- Some T50 firmware paths may use `Hid_simulator` split-channel packets instead of the 21-slot direct frame; CLI now exposes both probe families (`color-direct` and `color-sim116`).

## `0x2f` Flash Bridge (Live-Validated)

Based on static disassembly (`Hid_flash`) and live packet probes:

- Read 8 bytes (`Hid_flash` read helper, function `0x55c8cc`):
  - packet: `opcode=0x2f`, payload offset `2`, bytes `00 <addr_hi> <addr_lo> 00 00 00`
  - response payload bytes `8..15` contain the 8-byte block.
- Read dwords (`Hid_flash` dword read helper, function `0x55ccb4`):
  - packet byte `2 = 0x00`
  - packet dword `24..27 = count` (`1..2`)
  - packet dword `28..31 = address` (little-endian)
  - response payload starts at byte `32` (`count * 4` bytes).
- Write words (`Hid_flash` word writer helpers, `0x55ca00` / `0x55cabc`):
  - packet byte `2 = ((word_count - 1) << 3) + 1`
  - bytes `3..4 = addr_hi, addr_lo`
  - byte `5 = 0x00` (normal) or `0x80` (verify-mode variant)
  - data payload starts at byte `8` (`word_count * 2` bytes).
- Write dwords (`Hid_flash` dword writer helper, `0x55ce14`):
  - packet byte `2 = 0x01`
  - packet dword `24..27 = count` (`1..8`)
  - packet dword `28..31 = address`
  - data payload starts at byte `32` (`count * 4` bytes).

These are now first-class CLI utilities (`flash-read8`, `flash-read32`, `flash-write16`, `flash-write32`, `flash-scan8`).

## Persistence Probe Status (Current)

- Live read8 scan confirms stable nonzero blocks at `0x1c00`, `0x1d00`, `0x1e00`, `0x2d00`, `0x2e00`.
- Repeated DPI changes (`dpi-set` + `save` with `capture-v4`) did not alter coarse flash-read snapshots (`0x0000..0xff00`, step `0x100`) nor the targeted `0x1c00..0x2fff` step `0x10` scan.
- Current inference: existing `dpi-step`/`dpi-set` path is runtime-only for T50 and does not yet execute the full Bloody7 table+checksum flash update sequence.

## `Iom_adjustgun` Word-Table Flow (Static + Live Correlation)

- Disassembly around `0x417768` confirms this flash flow:
  - read header at base (`flash_read8`)
  - compute two 16-bit checksums over words `4..127`
  - stamp header words: `0xFFFF, 0xFFFF, checksum1, checksum2`
  - write 8 chunks (`16` words each) via `flash_write_words_verify` at `base + 0x00, 0x10, ... 0x70`
  - finalize with single-word marker `0xA4A4` via `flash_write_words` at `base`
- Live T50 readback at `0x1c00` (`a4 a4 ff ff ...`) matches this header shape (`marker + 0xFFFF + checksums`).
- Live `adjustgun-scan` currently reports two header bases on T50 (`0x1c00`, `0x1d00`), both matching `A4 A4 FF FF <checksum1> <checksum2>`.
- `mloody` now exposes this algorithm directly for controlled RE:

```bash
./build/mloody t50 adjustgun-write16 --addr 0x1c00 --data "<256-byte-hex>" --unsafe 1
./build/mloody t50 adjustgun-scan --from 0x1c00 --to 0x1fff --step 0x10
```

- This is intentionally unsafe and currently for reverse-engineering only.

## New Static RE Utility

- `tools/re/bloody7_adjustgun_map.py` extracts callsites to `Hid_flash` primitives and groups per-function primitive sequences.
- This is intended to isolate the exact `Iom_adjustgun` persistence path from generic lighting/config flows.
- Example:

```bash
python3 tools/re/bloody7_adjustgun_map.py \
  --json-out tmp/captures/bloody7_adjustgun_map.json
```

## Static Firmware/MCU Inference

From UTF-16 string clusters in `Bloody7.exe`:

- Legacy USB firmware template block includes:
  - `A60cir_P3332A_%.3X_%d` (T50-family candidate)
- Nearby MCU part block includes Sonix part strings:
  - `SN8F2253B`, `SN8F22E88B`, `SN8F2288`, followed by modern `SN32F247B`/`SN32F248B` entries.
- A static ordered-pair heuristic (scripted in `tools/re/bloody7_fw_mcu_map.py`) maps:
  - `A60cir_P3332A_%.3X_%d` -> `SN8F22E88B`
- A switch-table extractor (`tools/re/bloody7_fw_case_map.py`) now decodes part of the legacy firmware selector:
  - jump-table case `0x4EC` -> `A60cir_P3332A_%.3X_%d` (T50-family template)
  - other decoded neighbors include `0x4E0`/`0x4E4`/`0x4F0`/`0x4F4` mapped to `J95S`/`J90S`/`N81c`/`V9Mc` templates.

Confidence:

- Medium. The model-to-MCU pairing is inferred from ordered blocks and string-reference code paths, not yet proven by a direct struct decode or firmware header decode.

## Next RE Targets

- Isolate which opcode writes CPI table values directly (separate from simulator action stepping).
- Map kernel/core switch command path to simulator family changes (`15` vs `26/27`) using before/after `t50 capture` snapshots.
- Locate transaction(s) that commit CPI/core edits without touching lighting pages.
- Lift and decode the dispatch tables around firmware template references (`0x41af..`) and MCU references (`0x41de..0x422c`) to prove per-model MCU pairing without heuristics.
- Reverse the `.sn8encode5` header/layout enough to confirm the target MCU from encoded firmware blobs directly.
