# AGENTS.md

Notes for coding agents working on this repository: a Ghidra processor module for Renesas RX.

## Layout

- `data/languages/`: the processor definition. This is where nearly all changes go.
  - `rx62t.sinc`: the instruction specification, shared by both languages.
  - `rx62t_common.sinc`: shared definitions (spaces, registers).
  - `rx62t.slaspec` (LE) and `rx62t_be.slaspec` (BE): the per-language entry points.
  - `rx62t.cspec` (calling convention), `rx62t.pspec`, `rx62t.ldefs` (language list), `rx62t.opinion`.
- `src/main/java/rx62t/`: the *RX62T Raw Binary* loader (`RX62TLoader`, un-swaps BE code with the
  statistical code/data classifier in `RX62TBEClassifier`), the *RX62T Platform Setup* analyzer
  (`RX62TAnalyzer`) and the Ghidra-free scans they share (`RX62TBEUtils`). `test/run_tests.sh` and
  the install script build them into the extension's `lib/RX62T.jar`. The release zip holds the
  language files and `ghidra_scripts/`, but not the jar; only `build_release.sh --with-jar` adds it,
  to a `-local` zip for the builder's own machine that must never be published.
- `ghidra_scripts/`: the RX scripts (`RxOrphanFunctions.java`, `RxFixSignatures.java`,
  `RxUnlockSignatures.java`), shipped in the release zip and copied by the install script.
- `src/test/java/rx62t/`: dependency-free test mains for the scans and the classifier
  (`test/run_java_tests.sh`), and `RealisticImage.java`, the committed synthetic big-endian test
  image. `test/ghidra_scripts/RxLoaderTest.java`: headless loader and analyzer cases.
- `test/run_tests.sh`, `test/ghidra_scripts/RxVectorTest.java` and `test/vectors/*.vec`: the p-code
  vector suite. The `.vec` format is documented at the top of `RxVectorTest.java`.
- `tools/`: install, release and self-test scripts.

## Languages

- `rx62t:LE:32:default`: RX in little-endian mode, the usual case.
- `rx62t:BE:32:default`: RX in big-endian mode. Data is big-endian, and instruction tokens are
  little-endian. The code words of a raw image must be in fetch order. The *RX62T Raw Binary*
  loader un-swaps them on import (see README).

## Commands

```
test/run_tests.sh                    # compile both languages, run all vectors under both, then the loader suite
test/run_tests.sh test/vectors/X.vec # one vector file (no loader suite)
test/run_java_tests.sh               # build the jar, run the src/test/java test mains
tools/build_release.sh               # dist/ghidra_<ver>_PUBLIC_<date>_RX62T.zip
tools/build_release.sh --with-jar    # dist/..._RX62T-local.zip with lib/RX62T.jar (local install only; never publish)
tools/install_extension.sh           # copy and compile into an installed extension (Ghidra closed)
tools/test_install.sh                # self-test for the install script
tools/test_release.sh                # self-test for build_release.sh (plain and --with-jar zips)
```

The scripts use `GHIDRA_INSTALL_DIR` for a native Ghidra; otherwise they use the Flatpak
`org.ghidra_sre.Ghidra`. With the Flatpak, scratch paths must be under `$HOME` with no `.`-prefixed
elements, and `/tmp` is not visible. Every test needs only a checkout and Ghidra: tests read only
tracked files or build their inputs in code (the realistic big-endian image is
`src/test/java/rx62t/RealisticImage.java`); no environment variable points at test data. The only
external dependency is the Ghidra install.

## Rules

- Keep both languages green: `test/run_tests.sh` must end with `fail=0`. Add or extend a vector for
  every semantics change. Check semantics against the RXv1 software manual and encodings against
  binutils `opcodes/rx-decode.opc`.
- Never put backups or copies under `data/` of an extension or of this repo. Ghidra loads every
  `.ldefs` below `data/`, and a second copy gives "previously defined" and can override the fixes.
- Never touch a user's installed extension or Ghidra projects during tests. Run Ghidra headless
  with `-Dapplication.settingsdir=<scratch dir>`, as `test/run_tests.sh` does.
- Do not commit `dist/`, `build/` or compiled `.sla` files.
