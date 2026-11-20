#!/usr/bin/env bash
# Self-test for tools/install_extension.sh. Works only in scratch directories under
# $RX_TEST_SCRATCH (default $HOME/rx-install-test); the user's installed extension is never touched.
# The SLEIGH compiles run for real (the Flatpak, or GHIDRA_INSTALL_DIR if set), except in the
# native-mode case, which uses a stub Ghidra installation.
#
# usage: tools/test_install.sh
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL="$REPO/tools/install_extension.sh"
SCRATCH="${RX_TEST_SCRATCH:-$HOME/rx-install-test}"
MARKER=".rx-install-test-scratch"
case "$SCRATCH" in
    "$HOME"/*) ;; *) echo "SCRATCH must be under \$HOME: $SCRATCH" >&2; exit 2 ;;
esac
case "${SCRATCH#"$HOME"}" in
    */.*) echo "SCRATCH must not contain '.'-prefixed path elements: $SCRATCH" >&2; exit 2 ;;
esac

fails=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }

# A fresh fake extension with a stub languages dir, as left by an earlier install.
new_ext() {
    rm -rf "$SCRATCH/ext" "$SCRATCH/backups"
    mkdir -p "$SCRATCH/ext/data/languages" "$SCRATCH/backups"
    echo '<language_definitions/>' > "$SCRATCH/ext/data/languages/rx62t.ldefs"
    echo 'old' > "$SCRATCH/ext/data/languages/rx62t.sla"
}
# Never refuse because a real Ghidra happens to be open while the test runs.
run_install() { GHIDRA_RUNNING_CHECK_CMD=true EXT="$SCRATCH/ext" BACKUP_ROOT="$SCRATCH/backups" bash "$INSTALL" "$@"; }

[ -x "$INSTALL" ] || { echo "FAIL: $INSTALL missing or not executable"; exit 1; }
# Only ever delete a directory this script created (it carries the marker file), or an empty one.
if [ -d "$SCRATCH" ] && [ ! -f "$SCRATCH/$MARKER" ] && [ -n "$(ls -A "$SCRATCH")" ]; then
    echo "refusing to clear $SCRATCH: not empty and not created by this test (no $MARKER)" >&2; exit 2
fi
rm -rf "${SCRATCH:?}"; mkdir -p "$SCRATCH"; : > "$SCRATCH/$MARKER"

# 1. good install: backup outside EXT/data, .sla compiled
new_ext
if run_install "$REPO" > "$SCRATCH/good.log" 2>&1; then pass "good install exits 0"; else fail "good install failed (see $SCRATCH/good.log)"; fi
n_backups=$(find "$SCRATCH/backups" -mindepth 1 -maxdepth 1 -type d -name '*-languages.backup-*' | wc -l)
[ "$n_backups" -eq 1 ] && pass "one backup under BACKUP_ROOT" || fail "expected 1 backup under BACKUP_ROOT, found $n_backups"
[ -z "$(find "$SCRATCH/ext/data" -name '*backup*')" ] && pass "no backup under EXT/data" || fail "backup found under EXT/data"
for s in rx62t rx62t_be; do
    [ -s "$SCRATCH/ext/data/languages/$s.sla" ] && ! echo old | cmp -s - "$SCRATCH/ext/data/languages/$s.sla" \
        && pass "$s.sla compiled" || fail "$s.sla missing or stale"
done
[ -f "$SCRATCH/ext/INSTALLED_FROM.txt" ] && pass "INSTALLED_FROM.txt written" || fail "INSTALLED_FROM.txt missing"
if [ -f "$SCRATCH/ext/lib/RX62T.jar" ] && unzip -l "$SCRATCH/ext/lib/RX62T.jar" 2> /dev/null | grep -q 'rx62t/RX62TLoader.class'; then
    pass "lib/RX62T.jar built with RX62TLoader.class"
else
    fail "lib/RX62T.jar missing or without rx62t/RX62TLoader.class"
fi
scripts_ok=1
for f in "$REPO"/ghidra_scripts/*.java "$REPO/ghidra_scripts/README.txt"; do
    cmp -s "$f" "$SCRATCH/ext/ghidra_scripts/$(basename "$f")" || scripts_ok=
done
[ -n "$scripts_ok" ] && [ -f "$SCRATCH/ext/ghidra_scripts/RxOrphanFunctions.java" ] \
    && [ -f "$SCRATCH/ext/ghidra_scripts/RxFixSignatures.java" ] \
    && pass "ghidra_scripts installed and identical to the checkout" || fail "ghidra_scripts missing or different from the checkout"

# 2. SLEIGH compile error: non-zero exit, languages dir restored from the backup, and the jar
#    (or its absence) and ghidra_scripts (or its absence) restored byte-for-byte.
#    2a: a jar and scripts were installed before; 2b: neither was.
new_ext
mkdir -p "$SCRATCH/ext/lib"; echo 'old jar' > "$SCRATCH/ext/lib/RX62T.jar"
mkdir -p "$SCRATCH/ext/ghidra_scripts"; echo 'old script' > "$SCRATCH/ext/ghidra_scripts/RxOrphanFunctions.java"
echo 'user script' > "$SCRATCH/ext/ghidra_scripts/Mine.java"
rm -rf "$SCRATCH/scripts-before"; cp -a "$SCRATCH/ext/ghidra_scripts" "$SCRATCH/scripts-before"
rm -rf "$SCRATCH/broken"; mkdir -p "$SCRATCH/broken/data"
cp -a "$REPO/data/languages" "$SCRATCH/broken/data/"
cp -a "$REPO/src" "$REPO/ghidra_scripts" "$SCRATCH/broken/"
echo 'this is not sleigh ;' >> "$SCRATCH/broken/data/languages/rx62t.slaspec"
run_install "$SCRATCH/broken" > "$SCRATCH/broken.log" 2>&1; rc=$?
[ "$rc" -ne 0 ] && pass "broken slaspec exits non-zero ($rc)" || fail "broken slaspec exited 0"
backup=$(find "$SCRATCH/backups" -mindepth 1 -maxdepth 1 -type d -name '*-languages.backup-*' | head -1)
if [ -n "$backup" ] && diff -r "$backup" "$SCRATCH/ext/data/languages" > /dev/null; then
    pass "languages dir identical to backup after failed compile"
else
    fail "languages dir differs from backup after failed compile"
fi
[ ! -f "$SCRATCH/ext/INSTALLED_FROM.txt" ] && pass "no INSTALLED_FROM.txt after failure" || fail "INSTALLED_FROM.txt written on failure"
[ "$(cat "$SCRATCH/ext/lib/RX62T.jar" 2> /dev/null)" = 'old jar' ] \
    && pass "previous jar restored after failed compile" || fail "previous jar not restored after failed compile"
[ -z "$(find "$SCRATCH/ext/data" -name '*.jar*')" ] && pass "no jar backup under EXT/data" || fail "jar backup under EXT/data"
diff -r "$SCRATCH/scripts-before" "$SCRATCH/ext/ghidra_scripts" > /dev/null \
    && pass "previous ghidra_scripts restored after failed compile" || fail "ghidra_scripts not restored after failed compile"
[ -z "$(find "$SCRATCH/ext/data" -name '*scripts*')" ] && pass "no scripts backup under EXT/data" || fail "scripts backup under EXT/data"

new_ext
run_install "$SCRATCH/broken" > "$SCRATCH/broken2.log" 2>&1; rc=$?
{ [ "$rc" -ne 0 ] && [ ! -e "$SCRATCH/ext/lib/RX62T.jar" ]; } \
    && pass "no jar left behind after failed compile" || fail "jar left behind after failed compile (rc=$rc)"
[ ! -e "$SCRATCH/ext/ghidra_scripts" ] \
    && pass "no ghidra_scripts left behind after failed compile" || fail "ghidra_scripts left behind after failed compile"

# 3. extension never installed: exit 2, tell the user to install the zip once
rm -rf "$SCRATCH/ext"
GHIDRA_RUNNING_CHECK_CMD=true EXT="$SCRATCH/ext" BACKUP_ROOT="$SCRATCH/backups" bash "$INSTALL" "$REPO" > "$SCRATCH/missing.log" 2>&1; rc=$?
{ [ "$rc" -eq 2 ] && grep -q 'install the extension once' "$SCRATCH/missing.log"; } \
    && pass "missing EXT exits 2 with instruction" || fail "missing EXT: rc=$rc, $(head -1 "$SCRATCH/missing.log")"
[ ! -e "$SCRATCH/ext" ] && pass "missing EXT not created" || fail "missing EXT was created"

# 4. Ghidra running: exit 2, "quit Ghidra"; nothing changed
new_ext
GHIDRA_RUNNING_CHECK_CMD='echo /opt/ghidra/ghidraRun' EXT="$SCRATCH/ext" BACKUP_ROOT="$SCRATCH/backups" \
    bash "$INSTALL" "$REPO" > "$SCRATCH/running.log" 2>&1; rc=$?
{ [ "$rc" -eq 2 ] && grep -q 'quit Ghidra' "$SCRATCH/running.log"; } \
    && pass "running Ghidra exits 2 with 'quit Ghidra'" || fail "running Ghidra: rc=$rc, $(head -1 "$SCRATCH/running.log")"
[ "$(cat "$SCRATCH/ext/data/languages/rx62t.sla")" = old ] && pass "running Ghidra: nothing changed" || fail "running Ghidra: extension modified"

# 5. native mode with a stub installation: uses $GHIDRA_INSTALL_DIR/support/sleigh
new_ext
mkdir -p "$SCRATCH/fakeghidra/support"
cat > "$SCRATCH/fakeghidra/support/sleigh" <<'EOF'
#!/bin/sh
echo "stub sla for $1" > "$2"
EOF
chmod +x "$SCRATCH/fakeghidra/support/sleigh"
# stand-in for build_jar (a stub installation cannot compile): $1 = checkout, $2 = jar to write
printf '#!/bin/sh\necho "stub jar" > "$2"\n' > "$SCRATCH/fakejar.sh"; chmod +x "$SCRATCH/fakejar.sh"
RX_BUILD_JAR_CMD="$SCRATCH/fakejar.sh" GHIDRA_INSTALL_DIR="$SCRATCH/fakeghidra" run_install "$REPO" > "$SCRATCH/native.log" 2>&1; rc=$?
{ [ "$rc" -eq 0 ] && grep -q 'stub sla' "$SCRATCH/ext/data/languages/rx62t.sla"; } \
    && pass "native mode uses GHIDRA_INSTALL_DIR/support/sleigh" || fail "native mode: rc=$rc (see $SCRATCH/native.log)"

echo "test_install: $fails failure(s)"
[ "$fails" -eq 0 ] && [ -z "${KEEP_SCRATCH:-}" ] && rm -rf "${SCRATCH:?}"
[ "$fails" -eq 0 ]
