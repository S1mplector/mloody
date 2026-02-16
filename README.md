# mloody

`mloody` is an Objective-C macOS project scaffold for building a Bloody T50 mouse driver for macOS. 

The repository is intentionally layered so core behavior stays decoupled from macOS-specific I/O and transport details.

## Build

```bash
cmake -S . -B build
cmake --build build
```

## Test

```bash
ctest --test-dir build --output-on-failure
```

## CLI (Current)

```bash
./build/mloody list
./build/mloody probe
./build/mloody feature-set --report-id 0x07 --data "11 22 33"
./build/mloody feature-get --report-id 0x07 --length 16
./build/mloody feature-scan --from 0x01 --to 0x10 --length 16
./build/mloody t50 backlight-get
./build/mloody t50 backlight-set --level 2
./build/mloody t50 color-direct --r 255 --g 0 --b 0 --save 1 --strategy capture-v2
./build/mloody t50 core-get
./build/mloody t50 core-state
./build/mloody t50 core-set --core 2 --save 1 --strategy capture-v2
./build/mloody t50 save --strategy capture-v2
./build/mloody t50 command-read --opcode 0x11 --flag 0x00
./build/mloody t50 command-write --opcode 0x11 --data "ff 00 00" --offset 8
```

Commands default to T50-first selection when no explicit selector is provided.
T50 detection uses model-name matching (`T50`) and a known T50 product ID (`0x7F8D`).

- `list`: list supported Bloody devices with T50 flag.
- `probe`: select and print target device details (supports `--vid`, `--pid`, `--serial`, `--model`).
- `feature-set`: send a raw HID feature report payload.
- `feature-get`: read a raw HID feature report payload.
- `feature-scan`: sweep a report-id range and dump readable feature reports.
- `apply`: profile-intent use case placeholder; T50 packet mapping is still pending.
- `t50`: T50-focused command group for mapped and mapping-in-progress controls.

Selectors can be added to `apply`, `feature-set`, and `feature-get`:

```bash
./build/mloody feature-get --report-id 0x02 --length 32 --vid 0x09da --model T50
```

For `feature-set`, payload bytes are hex and can be written as `1122ff`, `11 22 ff`, or `0x11 0x22 0xff`.

## T50 Mapping Utilities

`mloody` now includes a T50 command channel built around the observed packet shape:

- report id: `0x07`
- packet length: `72`
- byte `0`: `0x07` magic
- byte `1`: opcode
- byte `4`: read/write flag (`0x00` read, `0x80` write)
- payload offset typically starts at byte `8`

Available tools:

```bash
./build/mloody t50 opcode-scan --from 0x10 --to 0x30 --flag 0x00
./build/mloody t50 dpi-probe --opcode 0x20 --dpi 1600
./build/mloody t50 polling-probe --opcode 0x21 --hz 1000
./build/mloody t50 lod-probe --opcode 0x22 --lod 2
./build/mloody t50 color-direct --r 255 --g 0 --b 0 --slots 20 --save 1 --strategy capture-v2
./build/mloody t50 color-probe --opcode 0x13 --r 255 --g 0 --b 0
./build/mloody t50 core-get
./build/mloody t50 core-state
./build/mloody t50 core-set --core 1 --save 1 --strategy capture-v2
./build/mloody t50 save --strategy capture-v2
```

`dpi-probe`/`polling-probe`/`lod-probe`/`color-probe` are mapping helpers; they are intentionally explicit about opcode so you can test and confirm behavior on your own device before we lock in stable named mappings.
`core-get` decodes from `opcode 0x1f` (`word @ payload[2..3]`, core = `(word & 0x3) + 1`), and `core-state` prints raw decode fields for RE.
`core-set` remains a candidate mapping (`write opcode 0x0c payload 06 80 <core>`) and should still be validated on hardware.
`t50 save` is an experimental persistence helper with strategies `quick`, `capture-v1`, and `capture-v2` (expanded pre/post transaction envelope from capture traces). Validate on real hardware with unplug/replug testing.
