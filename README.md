# mloodyt50-driver

`mloodyt50-driver` is a Bloody T50 mouse (LK) driver for macOS. 

> Upon request, I can reverse engineer other Bloody mice and make macOS drivers as well. Contact me on mehmetogluilgaz07@gmail.com. I decided to make this driver purely out of the reason that Bloody T50 is the only mouse I own, and I didn't want to pay for other mice. 

I intentionally layered the repository hexagonally so core behavior is decoupled from macOS-specific I/O and transport details.

Reverse-engineering notes for T50/Bloody7 are tracked in `docs/t50_bloody7_reverse_engineering.md`.

## Build

```bash
cmake -S . -B build
cmake --build build
```

## Test

```bash
ctest --test-dir build --output-on-failure
```

## CLI (Current state, I update it as I go)

```bash
./build/mloody list
./build/mloody probe
./build/mloody feature-set --report-id 0x07 --data "11 22 33"
./build/mloody feature-get --report-id 0x07 --length 16
./build/mloody feature-scan --from 0x01 --to 0x10 --length 16
./build/mloody t50 backlight-get
./build/mloody t50 backlight-set --level 2
./build/mloody t50 sled-profile-get
./build/mloody t50 sled-profile-set --index 3 --save 1 --strategy capture-v3
./build/mloody t50 sled-enable-get
./build/mloody t50 sled-enable-set --enabled 1 --save 1 --strategy capture-v3
./build/mloody t50 color-mode --mode open
./build/mloody t50 color-mode --mode effect
./build/mloody t50 color-direct --r 255 --g 0 --b 0 --frames 60 --save 0
./build/mloody t50 color-direct --r 255 --g 0 --b 0 --slot 2 --save 0
./build/mloody t50 color-zone --zone logo --r 255 --g 0 --b 0 --save 0
./build/mloody t50 color-sweep --r 255 --g 255 --b 0 --from 1 --to 21 --delay-ms 300
./build/mloody t50 color-sim116 --r 255 --g 0 --b 0 --index 0 --prepare 1 --save 0
./build/mloody t50 core-get
./build/mloody t50 core-state
./build/mloody t50 core-set --core 2 --verify 1 --retries 2 --save 1 --strategy capture-v4
./build/mloody t50 core-scan --from 1 --to 4 --verify 1 --restore 1 --save 0
./build/mloody t50 core-recover --core 1 --verify 1 --retries 3 --save 1 --strategy capture-v4
./build/mloody t50 save --strategy quick
./build/mloody t50 command-read --opcode 0x11 --flag 0x00
./build/mloody t50 command-write --opcode 0x11 --data "ff 00 00" --offset 8
./build/mloody t50 flash-read8 --addr 0x1c00
./build/mloody t50 flash-read32 --addr 0x2e00 --count 1
./build/mloody t50 flash-write16 --addr 0x1c00 --data "34 12 78 56" --verify 1 --unsafe 1
./build/mloody t50 flash-write32 --addr 0x2e00 --data "78 56 34 12" --unsafe 1
./build/mloody t50 flash-scan8 --from 0x1c00 --to 0x2f00 --step 0x100 --nonzero-only 1
./build/mloody t50 dpi-set --dpi 1600 --save 1 --strategy capture-v3
./build/mloody t50 dpi-step --action up --count 2
./build/mloody t50 dpi-step --action down --save 1 --strategy capture-v3
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
./build/mloody t50 dpi-set --dpi 1600 --save 1 --strategy capture-v3
./build/mloody t50 dpi-probe --opcode 0x20 --dpi 1600
./build/mloody t50 dpi-step --action up --count 3 --delay-ms 100
./build/mloody t50 dpi-step --action down --save 1 --strategy capture-v3
./build/mloody t50 polling-probe --opcode 0x21 --hz 1000
./build/mloody t50 lod-probe --opcode 0x22 --lod 2
./build/mloody t50 color-mode --mode open
./build/mloody t50 color-mode --mode effect
./build/mloody t50 color-direct --r 255 --g 0 --b 0 --slots 21 --frames 60 --save 0
./build/mloody t50 color-direct --r 255 --g 0 --b 0 --slot 2 --save 0
./build/mloody t50 color-zone --zone wheel --r 0 --g 255 --b 0 --save 0
./build/mloody t50 color-zone --zone wheel-indicator --r 255 --g 255 --b 0 --save 0
./build/mloody t50 color-sweep --r 255 --g 255 --b 0 --from 1 --to 21 --delay-ms 300
./build/mloody t50 color-sim116 --r 255 --g 0 --b 0 --from 0 --to 115 --delay-ms 300
./build/mloody t50 color-probe --opcode 0x13 --r 255 --g 0 --b 0
./build/mloody t50 sled-profile-get
./build/mloody t50 sled-profile-set --index 3 --save 1 --strategy capture-v3
./build/mloody t50 sled-enable-get
./build/mloody t50 sled-enable-set --enabled 1 --save 1 --strategy capture-v3
./build/mloody t50 core-get
./build/mloody t50 core-state
./build/mloody t50 core-set --core 1 --verify 1 --retries 2 --save 1 --strategy capture-v4
./build/mloody t50 core-scan --from 1 --to 4 --verify 1 --restore 1 --save 0
./build/mloody t50 core-recover --core 1 --verify 1 --retries 3 --save 1 --strategy capture-v4
./build/mloody t50 save --strategy quick
./build/mloody t50 flash-read8 --addr 0x1c00
./build/mloody t50 flash-read32 --addr 0x2e00 --count 1
./build/mloody t50 flash-scan8 --from 0x0000 --to 0xffff --step 0x0100 --nonzero-only 1
```

`dpi-set` targets a requested DPI using the default ladder (`400, 800, 1200, 1600, 2000, 3200, 4000`) by calibrating downward first and then stepping up; it defaults to persistence mode (`--save 1`, strategy `capture-v3`) so settings survive replug/restart.
`dpi-probe`/`polling-probe`/`lod-probe`/`color-probe` are mapping helpers; they are intentionally explicit about opcode so you can test and confirm behavior on your own device before we lock in stable named mappings.
`dpi-step` is an experimental CPI rocker simulator (`up`, `down`, `cycle`) that targets the observed simulator-family path (`opcode 0x0f` by default); it now supports repeated actions via `--count` and `--delay-ms`.
`color-mode` sends captured menu/mode transitions (`open`, `effect`, `discard`) over `opcode 0x03`. (`constant` is kept as a compatibility alias for `effect`.)
`color-direct`/`color-zone` now default to safer live-probe behavior: `--prepare 0`, `--save 0`, `--strategy quick`, and `--frames 1`.
`color-direct` currently targets a 21-slot direct RGB frame hypothesis for T50 packets.
`color-sweep` writes one slot at a time and is useful for discovering which physical LED channel maps to each slot on your exact hardware.
Use `--frames <n>` (for example `--frames 60`) to overwrite multiple animation frames with the same RGB payload when a single write only causes transient color flashes.
Use `--prepare 1` to run the captured preamble (`open` + `0x00 0x02`) before RGB payload writes while probing.
`color-zone` is a safer named wrapper around `color-direct` for common targets (`logo`, `wheel`, `wheel-indicator`, `rear`, `all`) and defaults to `--save 0` during RE.
Current mapping hypothesis for T50 packets: `logo=slot 15`, `wheel=slots 7,8,21`, `wheel-indicator=slot 21`, `rear=slots 1-6,9-14,16-20`, `all=slots 1-21`.
`color-sim116` replays Bloody7's split simulator packets (`06 07/08/09/0A/0B/0C`) with 116 logical color indices and is useful when rear/logo LEDs ignore the 21-slot direct frame path.
`sled-profile-set`/`sled-enable-set` are new profile-path probes from Bloody7 `Hid_sled` static calls (`opcode 0x15` / `0x16`, payload byte at offset `8`) and are intended for profile-backed rear LED experiments.
`sled-profile-get`/`sled-enable-get` are read probes; some firmware revisions may still return zeros even when write probes affect behavior.
`core-get` decodes from `opcode 0x1f` (`word @ payload[2..3]`, core = `(word & 0x3) + 1`), and `core-state` prints raw decode fields for RE.
`core-set` remains a candidate mapping (`write opcode 0x0c payload 06 80 <core>`) and now supports `--verify` + `--retries` for safer readback validation.
`core-scan` automates stepping through a core range (`--from/--to`) with optional readback verification, delay, and automatic restore to the initial core.
`core-recover` is a safety helper that reapplies a known core (default `1`) with verification and optional persistence (`--save 1 --strategy capture-v4` by default).
`t50 save` is an experimental persistence helper with strategies `quick`, `capture-v1`, `capture-v2`, `capture-v3`, `capture-v4`, and `major-sync`.
`flash-read8` and `flash-read32` expose low-level `0x2f` flash bridge reads discovered in static RE.
`flash-scan8` is a read-only mapper for finding nonzero flash windows quickly.
`flash-write16` and `flash-write32` expose invasive write primitives and require `--unsafe 1`.
`capture-v2` mirrors only the observed Windows "OK/save" tail (`03 03 0b 00`, `14`, `05`, `2f`, `0e`, `0f`, `0c`, `0a`).
`capture-v3` replays the fuller traced flow (warmup `03 06 05/06/02`, brightness menu open `03 03 0b 01`, brightness ramp `11:0..3` with `0a` ticks, then the same tail plus `03 06 05/06`) and remains the baseline persistence strategy.
`capture-v4` appends a `Hid_major` sync tail (`07`, `08`, `06`, `1e 01`, `0a`) after `capture-v3`.
