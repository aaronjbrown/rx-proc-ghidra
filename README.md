# rx-proc-ghidra

This Ghidra module adds support for disassembling and decompiling Renesas RX architecture binaries.

This module is a work in progress, but currently implements disassembly and decompilation rules for
most of the instructions supported by the RX62T processor.

## Languages

| Language id | Data byte order | Use for |
|---|---|---|
| `rx62t:LE:32:default` | little-endian | RX in little-endian mode (the usual case) |
| `rx62t:BE:32:default` | big-endian | RX in big-endian mode, with code presented in fetch order (see below) |

Both share one instruction specification (`rx62t.sinc`) and the same compiler spec (Renesas CC-RX ABI:
arguments in R1–R4 then the stack, R15 = address for a returned structure, return value in R1,
R6–R13 preserved, caller removes stack arguments).

### Big-endian mode

When an RX runs in big-endian mode, data in memory is big-endian, but the CPU still fetches
instructions as little-endian 32-bit words. In a raw big-endian flash image the code is therefore
byte-reversed within each aligned 32-bit word. To analyse such an image:

1. Un-swap the 32-bit words of the **code** regions only (leave constant data, strings and vector
   tables untouched), so the instruction stream is in fetch order.
2. Import with `rx62t:BE:32:default`. Instructions decode exactly as in the LE language, and
   multi-byte data (constant tables, vector tables, mixed-width accesses to RAM) reads big-endian.

Which regions are code is image-specific, so it is not done by this module.

## Install

### From the release zip

A release zip installs only into the Ghidra version in its name. For example,
`ghidra_12.1.3_PUBLIC_<date>_RX62T.zip` is for Ghidra 12.1.3, native or Flatpak.

1. In Ghidra, open *File → Install Extensions*.
2. Click `+` and pick the zip.
3. Restart Ghidra.

If an older RX62T is listed, uninstall it and restart Ghidra first.

To build the zip yourself, run `tools/build_release.sh`. It writes the zip to `dist/`. It compiles
the `.sla` files with the SLEIGH compiler of the Ghidra in `GHIDRA_INSTALL_DIR`. If that is unset,
it uses the Flatpak (`GHIDRA_FLATPAK=org.ghidra_sre.Ghidra`). The zip holds only the language
files. The Java sources under `src/` are unused template stubs, so they are not built.

### From source

To try changes from a checkout:

1. Install the zip once.
2. Start Ghidra, then quit it.
3. Run the install script:

```
GHIDRA_INSTALL_DIR=<ghidra install> tools/install_extension.sh    # native Ghidra
tools/install_extension.sh --flatpak                              # Flatpak Ghidra
```

The script copies the language files from the checkout into the installed extension and compiles
them. It uses these defaults:
- Native: `~/.config/ghidra/ghidra_<version>_PUBLIC/Extensions/RX62T`.
- Flatpak: `~/.var/app/<app id>/config/ghidra/ghidra_<version>_FLATPAK/Extensions/RX62T`.
- `GHIDRA_VERSION` defaults to `12.1.3`, and `EXT` overrides the extension directory.

The script first backs up the old `data/languages` to `~/ghidra_extension_backups`, or to
`BACKUP_ROOT` if set. If a SLEIGH compile fails, it puts the backup back. It refuses to run while
Ghidra is open. `tools/test_install.sh` tests it in scratch directories.

**Never keep backups under `Extensions/RX62T/data/`.** Ghidra loads every `.ldefs` file below
`data/`. So a copy such as `data/languages.bak/rx62t.ldefs` defines the languages a second time,
and the old definition can win. The log then shows
`Language rx62t:LE:32:default previously defined`.

## Known gaps

- **Unreachable-block warnings in dispatcher-style functions.** Some functions test RAM bytes with
  chains of `CMP`/`BNE`. These can still give many "Removing unreachable block" warnings. No
  branches inside instructions are involved. The cause is not yet known.
- **Leftover `in_stack_*` parameters.** These remain mostly where data tables were disassembled as
  code. That is mainly a seeding problem in the analysed image. A calling-convention cause has not
  been ruled out.
- **Decompiler Parameter ID is off by default** for this language. Enable it in the auto-analysis
  options for better function signatures. Headless, set it in a pre-script.

## Testing

`test/run_tests.sh` compiles the SLEIGH specs into a private staging directory and runs every vector
in `test/vectors/*.vec` headlessly under each language id in `rx62t.ldefs`: the bytes are
disassembled, the listing text checked, the instruction single-stepped in Ghidra's emulator and
registers, flags and memory compared. It also checks the register layout and the calling
conventions. The installed extension is not touched.

```
test/run_tests.sh                       # all vectors, all languages
test/run_tests.sh test/vectors/minmax.vec
```

With `GHIDRA_INSTALL_DIR=<ghidra install>` it uses that installation's `support/sleigh` and
`support/analyzeHeadless`; otherwise it uses the Flatpak (`GHIDRA_FLATPAK=org.ghidra_sre.Ghidra`,
`GHIDRA_VERSION=12.1.3`), in which case `STAGE` (default `$HOME/rx-proc-test`) must be under `$HOME`.
Only the files the script creates inside `STAGE` are removed. The vector format is documented at the
top of `test/ghidra_scripts/RxVectorTest.java`. Semantics are checked against the RXv1 software
manual (R01US0032EJ) and encodings against binutils `opcodes/rx-decode.opc`.
