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

## Next RE Targets

- Isolate which opcode writes CPI table values directly (separate from simulator action stepping).
- Map kernel/core switch command path to simulator family changes (`15` vs `26/27`) using before/after `t50 capture` snapshots.
- Locate transaction(s) that commit CPI/core edits without touching lighting pages.
