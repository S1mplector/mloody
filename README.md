# mloody

`mloody` is an Objective-C / Objective-C++ macOS project scaffold for building a Bloody mouse driver stack with a **hexagonal architecture**.

The repository is intentionally layered so core behavior stays decoupled from macOS-specific I/O and transport details.

## Architecture

- `src/domain`: Business rules, entities, value objects, and pure policy.
- `src/application`: Use cases and `ports` (`@protocol`) that define dependencies.
- `src/adapters`: Inbound/outbound adapter implementations.
- `src/bootstrap`: Composition root (`main.mm`) where concrete adapters are wired.
- `tests/unit`: Unit-style tests targeting application + domain through in-memory adapters.

See `docs/architecture.md` for dependency direction and extension points.

## Build

```bash
cmake -S . -B build
cmake --build build
```

## Test

```bash
ctest --test-dir build --output-on-failure
```

## CLI (Current Scaffold)

```bash
./build/mloody list
./build/mloody probe
./build/mloody feature-set --report-id 0x07 --data "11 22 33"
./build/mloody feature-get --report-id 0x07 --length 16
./build/mloody feature-scan --from 0x01 --to 0x10 --length 16
```

Commands default to T50-first selection when no explicit selector is provided.
T50 detection uses model-name matching (`T50`) and a known T50 product ID (`0x7F8D`).

- `list`: list supported Bloody devices with T50 flag.
- `probe`: select and print target device details (supports `--vid`, `--pid`, `--serial`, `--model`).
- `feature-set`: send a raw HID feature report payload.
- `feature-get`: read a raw HID feature report payload.
- `feature-scan`: sweep a report-id range and dump readable feature reports.
- `apply`: profile-intent use case placeholder; T50 packet mapping is still pending.

Selectors can be added to `apply`, `feature-set`, and `feature-get`:

```bash
./build/mloody feature-get --report-id 0x02 --length 32 --vid 0x09da --model T50
```

For `feature-set`, payload bytes are hex and can be written as `1122ff`, `11 22 ff`, or `0x11 0x22 0xff`.

## Notes for Real Driver Work

- Modern macOS driver development favors DriverKit/system extensions over legacy kernel extensions.
- Bloody protocol work (feature reports, endpoint behavior, profile packet format) should be implemented in the outbound transport adapter without changing domain or use-case code.
