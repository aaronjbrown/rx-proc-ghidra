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
byte-reversed within each aligned 32-bit word. The language `rx62t:BE:32:default` expects the code
in fetch order: instructions then decode exactly as in the LE language, and multi-byte data
(constant tables, vector tables, mixed-width accesses to RAM) reads big-endian.

The *RX62T Raw Binary* loader does the un-swapping. To import a raw big-endian RX flash image, you
need the image and its base address (the address its first byte is mapped to):

1. In *File → Import File*, pick the file, set *Format* to **RX62T Raw Binary** and *Language* to
   `rx62t:BE:32:default`.
2. Under *Options…*, set *Base address* to the image's base address (for example `0xFFF80000`).
   *Add RX RAM and peripheral I/O blocks* is on by default (see below).
3. Run auto-analysis.

When the file starts with reset code that sets INTB or EXTB, the import dialog preselects the
language whose byte order makes that code decode; otherwise neither language is preselected.

With *Add RX RAM and peripheral I/O blocks* on (headless: `-loader-rxMemoryMap true|false`), the
loader also adds two uninitialized read/write blocks from the RX62T memory map, so references to
RAM and I/O registers resolve:

| Block | Range | Notes |
|-------|-------|-------|
| `RAM` | `0x00000000`–`0x0007FFFF` | the on-chip RAM area; how much of it is populated varies by chip (see the memory map in the RX62T datasheet) |
| `PERIPH` | `0x00080000`–`0x000FFFFF` | peripheral I/O registers, marked volatile |

A block that would overlap the image (or any other existing block) is skipped whole, and the import
log says so.

Ghidra turns its *Scalar Operand References* analyzer (which makes references from immediates such as `MOV.L #imm32,Rn`) off by default for a program whose minimum address is 0, and the `RAM` block makes it 0. So when the image itself is not at 0, the loader turns that analyzer on, as it would be without the blocks. Blocks added later, for example by a pre-script, do not change the default, because Ghidra picks the defaults when the program is opened for analysis.

Programs imported with the memory map by a loader before 0.4.0 have the analyzer off: re-import them, or turn *Scalar Operand References* on in the auto-analysis options before analysing.

The loader also turns on the *Decompiler Parameter ID* analyzer for the program (Ghidra enables it
by default only for PE files), which gives better function signatures. Programs from other loaders
(ELF, *Raw Binary*) are left as Ghidra sets them: enable it by hand in the auto-analysis options, or
headless in a pre-script.

With *File → Add To Program*, the loader adds only the image: *Add RX RAM and peripheral I/O blocks*
defaults to off there, and the program's analysis options (*Decompiler Parameter ID*, *Scalar Operand References*) are left unchanged.

The loader decides which 32-bit words are code with a statistical code/data model (a byte-pair model
of code trained on the image itself, smoothed into long sections) and un-swaps only those. Constant
data, strings and the fixed vector table at `0xFFFFFF80` stay as stored. The original file bytes
are kept in the program. The loader adds the entry point `reset`. It is read from the reset vector
at `0xFFFFFFFC` if the image covers it and the vector points into the image. Otherwise it is the
image base.

The *RX62T Platform Setup* analyzer runs during auto-analysis. It finds the reset entry from the
reset vector, else the `reset` symbol, else the image base, and makes a function there. It reads
INTB and EXTB from the reset code at that entry, lays them down as labelled pointer arrays in
whichever blocks hold them, and makes functions at their handlers. INTB is `pointer[256]`. EXTB is
`pointer[31]` (ExtBase+00h to +78h), or `pointer[32]` at `0xFFFFFF80`, where the last slot is the
reset vector. Every INTB slot is labelled `int_vect_NNN` (vector number, NULL slots included) and
every EXTB slot `exc_vect_NN`. EXTB slots 20, 21, 23, 24, 25 and 30 (and 31 at `0xFFFFFF80`) get the
manual's name as an EOL comment, such as `Non-maskable interrupt`; a slot that already has an EOL
comment keeps it, and a user's label stays primary. It also marks the other pointer runs, one
`pointer` per slot and never as an array, so typing any entry later keeps its neighbours and their
references. A pointer may target any initialized block. Runs that overlap code are skipped, and
slots that already hold data are left alone. For a run in a **non-executable** block of at least
4 slots pointing into executable code, with at least 2 distinct targets, it makes functions at
those targets (dispatch tables). One dword of any value may sit between two such slots, so tables
of {handler, flag} entries count; two in a row end the run. A raw image imported as one block is executable
everywhere, so it gets no such functions until the image is split into code and data blocks with
correct execute flags, by hand in the Memory Map or in a pre-analysis script. Splitting blocks does
not re-run the analyzer: after a split by hand, run *Analysis → One Shot → RX62T Platform Setup*.
It reads memory as loaded, so it gives the same result for an image already in fetch order (un-swapped beforehand)
imported with Ghidra's own *Raw Binary* loader. For a little-endian image, use the *RX62T Raw
Binary* loader with `rx62t:LE:32:default`: it loads the file verbatim.

The loader and the analyzer are only in an extension built from a checkout: either a local zip
built with the jar (see [From a local zip with the loader](#from-a-local-zip-with-the-loader)) or
an install from source (see [From source](#from-source)). The release zip holds the language files
and `ghidra_scripts/`, but no loader jar.

## Install

### From the release zip

A release zip installs only into the Ghidra version in its name. For example,
`ghidra_12.1.3_PUBLIC_<date>_RX62T.zip` is for Ghidra 12.1.3, native or Flatpak.

1. In Ghidra, open *File → Install Extensions*.
2. Click `+` and pick the zip.
3. Restart Ghidra.

If an older RX62T is listed, uninstall it and restart Ghidra first.

A zip without the jar gives the languages and the scripts only: no *RX62T Raw Binary* loader and no
*RX62T Platform Setup* analyzer.

To build the zip yourself, run `tools/build_release.sh`. It writes the zip to `dist/`. It compiles
the `.sla` files with the SLEIGH compiler of the Ghidra in `GHIDRA_INSTALL_DIR`. If that is unset,
it uses the Flatpak (`GHIDRA_FLATPAK=org.ghidra_sre.Ghidra`). The zip holds the language files and
`ghidra_scripts/`. The loader and analyzer under `src/` are not in the zip.

### From a local zip with the loader

To get the loader and the analyzer while working only in the Ghidra GUI, build a zip that includes
`lib/RX62T.jar`:

1. Clone this repository.
2. Run `tools/build_release.sh --with-jar` (prefix it with `GHIDRA_INSTALL_DIR=<ghidra install>`
   for a native Ghidra; without it, the Flatpak is used). It writes
   `dist/ghidra_<version>_PUBLIC_<date>_RX62T-local.zip`, built from the committed sources of
   `HEAD` or of the revision given after the flag.
3. In Ghidra, open *File → Install Extensions*, click `+` and pick the `-local` zip.
4. Restart Ghidra.

The `-local` zip is for your own machine only. Upstream states no licence, so do not publish or
share it; the script prints a notice saying so.

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
them. It copies the scripts from `ghidra_scripts/` into the extension's `ghidra_scripts/`. It also
builds the loader and analyzer from `src/main/java` into the extension's `lib/RX62T.jar`. The jar
is built locally only: it is not in the release zip and not in git (`lib/*.jar` is ignored). It
uses these defaults:
- Native: `~/.config/ghidra/ghidra_<version>_PUBLIC/Extensions/RX62T`.
- Flatpak: `~/.var/app/<app id>/config/ghidra/ghidra_<version>_FLATPAK/Extensions/RX62T`.
- `GHIDRA_VERSION` defaults to `12.1.3`, and `EXT` overrides the extension directory.

The script first backs up the old `data/languages`, `lib/RX62T.jar` and `ghidra_scripts/` to
`~/ghidra_extension_backups`, or to `BACKUP_ROOT` if set. If the jar build or a SLEIGH compile
fails, it puts the backups back (a jar or scripts directory that did not exist before is removed
again). It refuses to run while Ghidra is open. `tools/test_install.sh` tests it in scratch
directories.

**Never keep backups under `Extensions/RX62T/data/`.** Ghidra loads every `.ldefs` file below
`data/`. So a copy such as `data/languages.bak/rx62t.ldefs` defines the languages a second time,
and the old definition can win. The log then shows
`Language rx62t:LE:32:default previously defined`.

## Scripts

Three scripts ship in `ghidra_scripts/` (Script Manager, category `RX`). All are self-contained and
do not need the loader jar.

- `RxOrphanFunctions.java`: run after auto-analysis. Creates functions for disassembled code that
  analysis left outside any function (code reached only through tail jumps or pointer tables).
- `RxFixSignatures.java`: run after auto-analysis, once Decompiler Parameter ID has finished (the
  RX62T Raw Binary loader turns it on). Gives functions still on the `unknown` calling convention
  the cspec default and sets returns with no found value to `void`. User-defined signatures are
  left alone. It refuses programs whose language is not an `rx62t` language.
- `RxUnlockSignatures.java`: run when `RxFixSignatures` ran before Decompiler Parameter ID had
  finished (mainly in the GUI), so functions were left with locked, parameterless signatures. It
  sets each function whose signature source is ANALYSIS and that has no parameters back to DEFAULT;
  user-defined and imported signatures are left alone. Then run *Analysis → One Shot → Decompiler
  Parameter ID*, and `RxFixSignatures` again. It refuses programs whose language is not an `rx62t`
  language.

## Known gaps

- **Unreachable-block warnings in dispatcher-style functions.** Some functions test RAM bytes with
  chains of `CMP`/`BNE`. These can still give many "Removing unreachable block" warnings. No
  branches inside instructions are involved. The cause is not yet known.
- **Leftover `in_stack_*` parameters.** These remain mostly where data tables were disassembled as
  code. That is mainly a seeding problem in the analysed image. A calling-convention cause has not
  been ruled out.
- **Pointer-run detection is heuristic.** It runs only for raw-image imports (*RX62T Raw Binary*
  and *Raw Binary*); for other formats, such as ELF, the analyzer lays only the reset entry, the
  INTB/EXTB vector tables and their handlers. A run only marks its slots as pointers (one `pointer`
  per slot); it does not say where a table starts or ends, so the analyzer never types runs as
  arrays. The analyzer marks pointer runs before it disassembles the reset code and handlers, so a
  false-positive run over real code would stop disassembly at that point. For raw images based at
  0, zeros and small integers look like pointers, so runs can be over-detected. The same happens
  in any image when an *initialized* block sits at address 0, such as RAM added through the Memory
  Map dialog with its default of initialized: tables of small integers then read as pointers into
  it and are marked one pointer per slot. For big-endian images imported with the *RX62T Raw Binary*
  loader, detected pointer runs are already classified as data.

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

With no vector-file arguments, `test/run_tests.sh` also builds `lib/RX62T.jar` into the staged
extension and runs the loader/analyzer suite (`test/ghidra_scripts/RxLoaderTest.java`) on synthetic
images; the final `RXTEST TOTAL` line covers both suites. `test/run_java_tests.sh` runs the pure-Java
tests of the endianness classifier and helpers under `src/test/java` (no Ghidra headless run). Both
pin the classifier on a committed realistic big-endian image built in code (`RealisticImage.java`):
its exact code/data/fill blocks, and the full load and analysis of it. For the loader suite,
`test/run_tests.sh` also compiles `src/test/java` into `lib/RX62T-tests.jar` of the staged extension
only; that jar is never installed or released. Every test needs only a checkout and Ghidra: no
other files or environment variables.

`tools/test_install.sh` tests the install script, and `tools/test_release.sh` tests
`tools/build_release.sh`: the plain and `--with-jar` zips, a jar built from a given revision, a
failed jar build, and a headless Ghidra run that loads the loader and the analyzer from the
installed `-local` zip. Both work in scratch directories under `$HOME` only.
