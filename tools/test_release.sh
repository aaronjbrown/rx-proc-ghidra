#!/usr/bin/env bash
# Self-test for tools/build_release.sh. Works only in scratch directories under $RX_TEST_SCRATCH
# (default $HOME/rx-release-test); the repo's dist/ and the user's installed extensions are never
# touched. The SLEIGH compiles and the Ghidra run are real (the Flatpak, or GHIDRA_INSTALL_DIR if set).
#
# usage: tools/test_release.sh
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
RELEASE="$REPO/tools/build_release.sh"
SCRATCH="${RX_TEST_SCRATCH:-$HOME/rx-release-test}"
MARKER=".rx-release-test-scratch"
case "$SCRATCH" in
    "$HOME"/*) ;; *) echo "SCRATCH must be under \$HOME: $SCRATCH" >&2; exit 2 ;;
esac
case "${SCRATCH#"$HOME"}" in
    */.*) echo "SCRATCH must not contain '.'-prefixed path elements: $SCRATCH" >&2; exit 2 ;;
esac

if [ -n "${GHIDRA_INSTALL_DIR:-}" ]; then
    props="$GHIDRA_INSTALL_DIR/Ghidra/application.properties"
    [ -f "$props" ] || { echo "not a Ghidra installation: $GHIDRA_INSTALL_DIR" >&2; exit 2; }
    GHIDRA_VERSION=$(sed -n 's/^application.version=//p' "$props")
    GHIDRA_RELEASE=$(sed -n 's/^application.release.name=//p' "$props")
    run_ghidra() { JAVA_TOOL_OPTIONS="-XX:-UsePerfData -Dapplication.settingsdir=$SCRATCH/settings" "$GHIDRA_INSTALL_DIR/support/$1" "${@:2}"; }
else
    GHIDRA_FLATPAK="${GHIDRA_FLATPAK:-org.ghidra_sre.Ghidra}"
    GHIDRA_VERSION="${GHIDRA_VERSION:-12.1.3}"
    GHIDRA_RELEASE="${GHIDRA_RELEASE:-FLATPAK}"
    run_ghidra() { flatpak run --env=JAVA_TOOL_OPTIONS="-XX:-UsePerfData -Dapplication.settingsdir=$SCRATCH/settings" --command="/app/lib/ghidra/support/$1" "$GHIDRA_FLATPAK" "${@:2}"; }
fi

fails=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }
count() { find "$1" -maxdepth 1 -name "$2" 2> /dev/null | wc -l; }
# jar_has <zip> <class>: the zip's RX62T/lib/RX62T.jar contains <class>
jar_has() { unzip -p "$1" RX62T/lib/RX62T.jar > "$SCRATCH/probe.jar" 2> /dev/null && unzip -l "$SCRATCH/probe.jar" | grep -q "$2"; }
# build <dist dir> <script> <args...>: runs a build_release.sh with DIST_DIR and BUILD_DIR in scratch
build() {
    local dist="$1" script="$2"; shift 2
    mkdir -p "$dist"
    DIST_DIR="$dist" BUILD_DIR="$dist-build" bash "$script" "$@" > "$dist.out" 2> "$dist.err"
}

[ -x "$RELEASE" ] || { echo "FAIL: $RELEASE missing or not executable"; exit 1; }
# Only ever delete a directory this script created (it carries the marker file), or an empty one.
if [ -d "$SCRATCH" ] && [ ! -f "$SCRATCH/$MARKER" ] && [ -n "$(ls -A "$SCRATCH")" ]; then
    echo "refusing to clear $SCRATCH: not empty and not created by this test (no $MARKER)" >&2; exit 2
fi
rm -rf "${SCRATCH:?}"; mkdir -p "$SCRATCH"; : > "$SCRATCH/$MARKER"

# 1. plain build: the old name, and no lib/ entry
if build "$SCRATCH/dist1" "$RELEASE"; then pass "plain build exits 0"; else fail "plain build failed (see $SCRATCH/dist1.err)"; fi
[ "$(count "$SCRATCH/dist1" '*_RX62T.zip')" -eq 1 ] && [ "$(count "$SCRATCH/dist1" '*')" -eq 2 ] \
    && pass "plain build writes one *_RX62T.zip to DIST_DIR" || fail "plain build: DIST_DIR holds $(ls "$SCRATCH/dist1" 2> /dev/null | tr '\n' ' ')"
plain=$(find "$SCRATCH/dist1" -name '*_RX62T.zip' | head -1)
[ -n "$plain" ] && ! unzip -l "$plain" | grep -q 'RX62T/lib/' && pass "plain zip has no lib/ entry" \
    || fail "plain zip missing or has a lib/ entry"

# 2. --with-jar: a -local zip with the jar, and the notice
if build "$SCRATCH/dist2" "$RELEASE" --with-jar; then pass "--with-jar exits 0"; else fail "--with-jar failed (see $SCRATCH/dist2.err)"; fi
[ "$(count "$SCRATCH/dist2" '*_RX62T-local.zip')" -eq 1 ] && [ "$(count "$SCRATCH/dist2" '*')" -eq 2 ] \
    && pass "--with-jar writes one *_RX62T-local.zip" || fail "--with-jar: DIST_DIR holds $(ls "$SCRATCH/dist2" 2> /dev/null | tr '\n' ' ')"
local_zip=$(find "$SCRATCH/dist2" -name '*_RX62T-local.zip' | head -1)
[ -n "$local_zip" ] && unzip -l "$local_zip" | grep -q 'RX62T/lib/RX62T.jar' && pass "-local zip lists RX62T/lib/RX62T.jar" \
    || fail "-local zip missing or without RX62T/lib/RX62T.jar"
[ -n "$local_zip" ] && jar_has "$local_zip" rx62t/RX62TLoader.class && jar_has "$local_zip" rx62t/RX62TAnalyzer.class \
    && pass "jar has RX62TLoader and RX62TAnalyzer" || fail "jar without RX62TLoader/RX62TAnalyzer classes"
grep -q 'do not publish' "$SCRATCH/dist2.err" && pass "--with-jar prints the do-not-publish notice" \
    || fail "no do-not-publish notice on stderr"

# 3. the jar is built from the given revision. The clone holds only committed files, so it gets this
#    working tree's build_release.sh and java_env.sh, the scripts under test.
CLONE="$SCRATCH/clone"
git clone -q "$REPO" "$CLONE"
cp "$REPO/tools/build_release.sh" "$REPO/tools/java_env.sh" "$CLONE/tools/"
echo 'package rx62t; final class ReleaseRevMarker {}' > "$CLONE/src/main/java/rx62t/ReleaseRevMarker.java"
git -C "$CLONE" add src/main/java/rx62t/ReleaseRevMarker.java
git -C "$CLONE" -c user.name=test -c user.email=test@invalid commit -q -m marker
build "$SCRATCH/dist3a" "$CLONE/tools/build_release.sh" --with-jar HEAD~1
z=$(find "$SCRATCH/dist3a" -name '*-local.zip' | head -1)
[ -n "$z" ] && jar_has "$z" rx62t/RX62TLoader.class && ! jar_has "$z" rx62t/ReleaseRevMarker.class \
    && pass "--with-jar HEAD~1 builds the jar from HEAD~1" || fail "--with-jar HEAD~1: jar missing or has the marker class"
build "$SCRATCH/dist3b" "$CLONE/tools/build_release.sh" --with-jar HEAD
z=$(find "$SCRATCH/dist3b" -name '*-local.zip' | head -1)
[ -n "$z" ] && jar_has "$z" rx62t/ReleaseRevMarker.class \
    && pass "--with-jar HEAD builds the jar from HEAD" || fail "--with-jar HEAD: jar missing or without the marker class"

# 4. Java source that does not compile: non-zero exit and no -local zip
echo 'class {' > "$CLONE/src/main/java/rx62t/Broken.java"
git -C "$CLONE" add src/main/java/rx62t/Broken.java
git -C "$CLONE" -c user.name=test -c user.email=test@invalid commit -q -m broken
build "$SCRATCH/dist4" "$CLONE/tools/build_release.sh" --with-jar; rc=$?
[ "$rc" -ne 0 ] && pass "broken source exits non-zero ($rc)" || fail "broken source exited 0"
[ "$(count "$SCRATCH/dist4" '*-local.zip')" -eq 0 ] && pass "broken source leaves no -local zip" \
    || fail "broken source left a -local zip"

# 5. Ghidra loads the jar from the installed zip: the loader and the analyzer are both there
EXTS="$SCRATCH/settings/ghidra/ghidra_${GHIDRA_VERSION}_${GHIDRA_RELEASE}/Extensions"
mkdir -p "$EXTS" "$SCRATCH/proj"
head -c 64 /dev/zero > "$SCRATCH/tiny.bin"
if [ -n "$local_zip" ] && unzip -q "$local_zip" -d "$EXTS"; then
    run_ghidra analyzeHeadless "$SCRATCH/proj" t -import "$SCRATCH/tiny.bin" -loader RX62TLoader \
        -loader-baseAddr 0x1000 -processor rx62t:LE:32:default -postScript RxReleaseCheck.java \
        -scriptPath "$REPO/test/ghidra_scripts" -deleteProject > "$SCRATCH/headless.log" 2>&1
    grep -q 'RXRELEASE loader RX62T Raw Binary' "$SCRATCH/headless.log" && pass "installed zip offers the RX62T Raw Binary loader" \
        || fail "loader not used (see $SCRATCH/headless.log)"
    grep -q 'RXRELEASE analyzer yes' "$SCRATCH/headless.log" && pass "installed zip registers RX62T Platform Setup" \
        || fail "analyzer not registered (see $SCRATCH/headless.log)"
else
    fail "could not install the -local zip into $EXTS"
fi

# 6. usage
bash "$RELEASE" --bogus > /dev/null 2>&1; rc=$?
[ "$rc" -eq 2 ] && pass "unknown option exits 2" || fail "unknown option exited $rc"

[ "$fails" -eq 0 ] && echo "ALL PASS" || echo "$fails FAILED"
[ "$fails" -eq 0 ]
