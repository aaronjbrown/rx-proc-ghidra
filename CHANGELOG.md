# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.0 - 2026-11-23

### Added

- **RX62T Platform Setup analyzer: vector slot labels.** Every slot of the INTB array is labelled `int_vect_NNN` (`000`–`255`, NULL slots included) and every slot of the EXTB array `exc_vect_NN` (`00`–`30`, or `00`–`31` at `0xFFFFFF80`). EXTB slots 20, 21, 23, 24, 25 and 30 (and 31, `Reset`, at `0xFFFFFF80`) get the manual's name as an EOL comment (RXv3 R01US0316EJ0100 and RXv2 R01US0071EJ0100, Figure 1.8). Existing labels and EOL comments are kept, and a user's label stays primary.
- **RX62T Platform Setup analyzer: functions at code-pointer targets.** For a run in a non-executable block of at least 4 slots pointing into initialized executable memory, with at least 2 distinct targets, a function is made at each target. One dword of any value may sit between two such slots, so tables of {handler, flag} entries count. Targets whose first word is `FFFFFFFF` (erased flash) do not count. A raw image imported as one executable block gets no such functions until code and data are split into blocks with correct execute flags (then run the analyzer again, for example as a one-shot analysis).
- **`RxUnlockSignatures` script.** It sets ANALYSIS signatures with no parameters back to DEFAULT, for when `RxFixSignatures` ran before Decompiler Parameter ID had finished. Then run Decompiler Parameter ID as a one-shot analysis and `RxFixSignatures` again.
- **`tools/build_release.sh --with-jar`.** It builds `..._RX62T-local.zip`, which includes `lib/RX62T.jar` built from the same revision, for installing the loader and the analyzer from the GUI on your own machine. Upstream states no licence, so this zip must not be published. A new `DIST_DIR` sets the output directory.
- **`tools/test_release.sh`**, a self-test for `build_release.sh`, which also checks headlessly that Ghidra loads the loader and the analyzer from an installed `-local` zip.

### Changed

- **RX62T Platform Setup analyzer: pointer runs.** Detected pointer runs are marked one `pointer` per slot (Ghidra's default pointer type, the one its operand analyzer creates) instead of one `pointer[N]` array. A run no longer claims where a table starts or ends. Slots that already hold data are left alone, and NULL slots stay undefined. The word `0xFFFFFFFF` (erased flash) is never taken for a pointer. Programs analysed under 0.3.0 keep their `pointer[N]` arrays when analysed again, because existing data wins; re-import them to get per-slot pointers.

### Fixed

- **Fewer references with the memory map.** Ghidra turns its *Scalar Operand References* analyzer off by default when a program's minimum address is 0, and the loader's `RAM` block at `0x00000000` made it 0. Imports with *Add RX RAM and peripheral I/O blocks* on therefore got no references from immediates such as `MOV.L #imm32,Rn`, into RAM, I/O or code: about 10–20% fewer references than the same import with the option off. The loader now turns that analyzer on when its blocks moved the minimum address to 0, so both imports give the same references. An image loaded at 0 keeps Ghidra's default (off).
- **Lost references.** Typing the first entry of a detected run, for example from a script, no longer removes the other entries and their references.
- **EXTB size.** EXTB is laid as 31 entries (ExtBase+00h to +78h), or 32 at `0xFFFFFF80`, where the last slot is the reset vector (RXv2 and RXv3 software manuals, section 1.7.1). It was 32 everywhere.
- **Programs with several memory blocks.** The reset entry is resolved once per program (reset vector, else the `reset` symbol, else the image base), and only the reset code there is scanned. INTB and EXTB are laid in whichever blocks hold them, and handler functions stay in the handler's block. Pointer targets in any initialized block count. Before, each block was scanned on its own, so tables in other blocks were never laid, and the start of any block could be taken for reset code.
- **Overlapping vector tables.** When the reset code sets INTB and EXTB to overlapping ranges, the table set up first is kept and the other is not laid. Before, laying the second cleared the first.

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
