# AGENTS.md

Notes for coding agents working on this repository: a Ghidra processor module for Renesas RX.

## Layout

- `data/languages/`: the processor definition. This is where nearly all changes go.
  - `rx62t.sinc`: the instruction specification, shared by both languages.
  - `rx62t_common.sinc`: shared definitions (spaces, registers).
  - `rx62t.slaspec` (LE) and `rx62t_be.slaspec` (BE): the per-language entry points.
  - `rx62t.cspec` (calling convention), `rx62t.pspec`, `rx62t.ldefs` (language list), `rx62t.opinion`.
- `src/main/java/rx62t/`: GhidraDev template stubs for a loader and an analyzer. They are unused and
  are not built for releases.
- `test/run_tests.sh`, `test/ghidra_scripts/RxVectorTest.java` and `test/vectors/*.vec`: the p-code
  vector suite. The `.vec` format is documented at the top of `RxVectorTest.java`.
- `tools/`: install, release and self-test scripts.

## Languages

- `rx62t:LE:32:default`: RX in little-endian mode, the usual case.
- `rx62t:BE:32:default`: RX in big-endian mode. Data is big-endian, and instruction tokens are
  little-endian. The code regions of a raw image must first be un-swapped per 32-bit word (see
  README).

## Commands

```
test/run_tests.sh                    # compile both languages, run all vectors under both
test/run_tests.sh test/vectors/X.vec # one vector file
tools/build_release.sh               # dist/ghidra_<ver>_PUBLIC_<date>_RX62T.zip
tools/install_extension.sh           # copy and compile into an installed extension (Ghidra closed)
tools/test_install.sh                # self-test for the install script
```

The scripts use `GHIDRA_INSTALL_DIR` for a native Ghidra; otherwise they use the Flatpak
`org.ghidra_sre.Ghidra`. With the Flatpak, scratch paths must be under `$HOME` with no `.`-prefixed
elements, and `/tmp` is not visible.

## Rules

- Keep both languages green: `test/run_tests.sh` must end with `fail=0`. Add or extend a vector for
  every semantics change. Check semantics against the RXv1 software manual and encodings against
  binutils `opcodes/rx-decode.opc`.
- Never put backups or copies under `data/` of an extension or of this repo. Ghidra loads every
  `.ldefs` below `data/`, and a second copy gives "previously defined" and can override the fixes.
- Never touch a user's installed extension or Ghidra projects during tests. Run Ghidra headless
  with `-Dapplication.settingsdir=<scratch dir>`, as `test/run_tests.sh` does.
- Do not commit `dist/`, `build/` or compiled `.sla` files.
