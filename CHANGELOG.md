# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0 - 2026-11-20

### Added

- **RX62T Raw Binary loader.** It imports a raw RX flash image at a chosen *Base address*
  (headless: `-loader-baseAddr`) as one `flash` block. The original file bytes are kept in
  Ghidra's FileBytes.
  - **Big-endian language:** code words are put back into instruction-fetch order using a
    statistical code/data classifier. Data, fill and the RX fixed vector table
    (`0xFFFFFF80`–`0xFFFFFFFF`) are kept as stored.
  - **Reset entry:** taken from the reset vector when the image covers it, otherwise the
    image base.
  - **Suggested language:** the import dialog suggests the byte order whose reset code sets
    INTB/EXTB.
  - **Memory map:** the option *Add RX RAM and peripheral I/O blocks* (on by default;
    headless: `-loader-rxMemoryMap`) adds uninitialized `RAM` (`0x00000000`–`0x0007FFFF`) and
    volatile `PERIPH` (`0x00080000`–`0x000FFFFF`) blocks.
  - **Parameter ID:** Decompiler Parameter ID is turned on for programs this loader imports.
  - **Add To Program:** adds only the image.
- **RX62T Platform Setup analyzer.** It labels the reset handler, the INTB/EXTB vector tables
  (as pointer arrays, with a function for each handler) and, for raw-image imports,
  code-pointer tables. It never removes instructions or user-defined data.
- **pspec and opinion:** a `__reset_vector` default symbol at `0xFFFFFFFC`, and an
  `rx62t.opinion` entry for the loader.
- **Scripts:** `RxOrphanFunctions` and `RxFixSignatures` in `ghidra_scripts/` (category
  *RX*).
- **Tests:** `test/run_java_tests.sh` for the pure-Java classifier and scans, and a headless
  loader/analyzer suite in `test/run_tests.sh`, which includes a committed synthetic
  big-endian test image. Every test runs from a plain checkout and a Ghidra install.

### Changed

- **Install script:** `tools/install_extension.sh` now builds and installs `lib/RX62T.jar`
  and `ghidra_scripts/`, backing each up and restoring it if the install fails.
- **Release zip:** it ships the language files and `ghidra_scripts/`. The loader jar is built
  from a checkout and is not included.
- **Vector tests:** `RxVectorTest` uses `PcodeEmulator` instead of the deprecated
  `EmulatorHelper`.

### Removed

- The unused GhidraDev template stubs for the loader and analyzer.

## 0.2.0 - 2026-11-15

### Added

- **Big-endian language:** `rx62t:BE:32:default`, with big-endian data and little-endian
  instruction tokens.
- **Instructions:** the `XCHG` memory forms, which were previously unimplemented.
- **Tests:** a headless p-code vector suite (`test/run_tests.sh`, `test/vectors/*.vec`) that
  runs under both languages and checks the register layout and calling conventions.
- **Tools:** `tools/install_extension.sh` (native or Flatpak Ghidra, with backup and
  restore), `tools/test_install.sh`, and `tools/build_release.sh` (release zip for Ghidra
  12.1.3).
- **Docs:** README sections on the languages, big-endian mode, install, testing and known
  gaps, and `AGENTS.md`.
- **From upstream (2021):** a stack-based `cdecl` calling convention.

### Fixed

- **Instruction semantics:**
  - ADC/SBB use the incoming carry, and ROLC/RORC rotate through C.
  - DIV/DIVU set the overflow flag.
  - MAX/MIN compare signed values, and MAX selects the greater.
  - SHAR `#imm,Rs,Rd` sets Z/S from the result, and SHLL flags are computed without branches.
  - RTSD frame size, FTOI/FTOU truncation, SUNTIL/SWHILE, SCcnd, STZ/STNZ, register-numbered
    bit ops on memory, and `memex=UB` ALU register sources.
- **Compiler spec:** R15 is not an argument register, and `extrapop=4`.
- **Registers:** ACC no longer overlaps EXTB.
- **From upstream (2021):** JMP operations act as real calls, PUSHM/POPM avoid branches, and
  multiple return values were removed for Ghidra 10.1.

## 0.1.0 - 2019-06-26

- First release of the RX62T SLEIGH processor module (little-endian).
