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
./build/mloody t50 color-mode --mode open
./build/mloody t50 color-mode --mode effect
./build/mloody t50 color-direct --r 255 --g 0 --b 0 --frames 60 --save 0
./build/mloody t50 color-direct --r 255 --g 0 --b 0 --slot 2 --save 0
./build/mloody t50 color-zone --zone logo --r 255 --g 0 --b 0 --save 0
./build/mloody t50 color-sweep --r 255 --g 255 --b 0 --from 1 --to 21 --delay-ms 300
./build/mloody t50 core-get
./build/mloody t50 core-state
./build/mloody t50 core-set --core 2 --save 1 --strategy capture-v2
./build/mloody t50 save --strategy quick
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
./build/mloody t50 color-mode --mode open
./build/mloody t50 color-mode --mode effect
./build/mloody t50 color-direct --r 255 --g 0 --b 0 --slots 21 --frames 60 --save 0
./build/mloody t50 color-direct --r 255 --g 0 --b 0 --slot 2 --save 0
./build/mloody t50 color-zone --zone wheel --r 0 --g 255 --b 0 --save 0
./build/mloody t50 color-zone --zone wheel-indicator --r 255 --g 255 --b 0 --save 0
./build/mloody t50 color-sweep --r 255 --g 255 --b 0 --from 1 --to 21 --delay-ms 300
./build/mloody t50 color-probe --opcode 0x13 --r 255 --g 0 --b 0
./build/mloody t50 core-get
./build/mloody t50 core-state
./build/mloody t50 core-set --core 1 --save 1 --strategy capture-v2
./build/mloody t50 save --strategy quick
```

`dpi-probe`/`polling-probe`/`lod-probe`/`color-probe` are mapping helpers; they are intentionally explicit about opcode so you can test and confirm behavior on your own device before we lock in stable named mappings.
`color-mode` sends captured menu/mode transitions (`open`, `effect`, `discard`) over `opcode 0x03`. (`constant` is kept as a compatibility alias for `effect`.)
`color-direct`/`color-zone` now default to safer live-probe behavior: `--prepare 0`, `--save 0`, `--strategy quick`, and `--frames 1`.
`color-direct` currently targets a 21-slot direct RGB frame hypothesis for T50 packets.
`color-sweep` writes one slot at a time and is useful for discovering which physical LED channel maps to each slot on your exact hardware.
Use `--frames <n>` (for example `--frames 60`) to overwrite multiple animation frames with the same RGB payload when a single write only causes transient color flashes.
Use `--prepare 1` to run the captured preamble (`open` + `0x00 0x02`) before RGB payload writes while probing.
`color-zone` is a safer named wrapper around `color-direct` for common targets (`logo`, `wheel`, `wheel-indicator`, `rear`, `all`) and defaults to `--save 0` during RE.
Current mapping hypothesis for T50 packets: `logo=slot 15`, `wheel=slots 7,8,21`, `wheel-indicator=slot 21`, `rear=slots 1-6,9-14,16-20`, `all=slots 1-21`.
`core-get` decodes from `opcode 0x1f` (`word @ payload[2..3]`, core = `(word & 0x3) + 1`), and `core-state` prints raw decode fields for RE.
`core-set` remains a candidate mapping (`write opcode 0x0c payload 06 80 <core>`) and should still be validated on hardware.
`t50 save` is an experimental persistence helper with strategies `quick`, `capture-v1`, and `capture-v2` (expanded pre/post transaction envelope from capture traces). Prefer `quick` during live color testing, as `capture-v2` can trigger temporary LED mode transitions.
