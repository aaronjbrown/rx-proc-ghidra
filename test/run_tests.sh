#!/usr/bin/env bash
# Compile the SLEIGH languages of this extension into a private staging copy and run the
# p-code vector suite (test/vectors/*.vec) headlessly under every language id in rx62t.ldefs.
# The user's installed extension is never touched: Ghidra runs with
# -Dapplication.settingsdir pointing at the staging directory.
#
# usage: test/run_tests.sh [vector-file ...]
# env:   GHIDRA_INSTALL_DIR  a Ghidra installation; uses its support/sleigh and support/analyzeHeadless
#        otherwise the Flatpak: GHIDRA_FLATPAK (org.ghidra_sre.Ghidra), GHIDRA_VERSION (12.1.3),
#        GHIDRA_RELEASE (FLATPAK)
#        STAGE  scratch directory (default $HOME/rx-proc-test); only the files this script creates in
#               it are removed. With the Flatpak it must be under $HOME with no '.'-prefixed elements.
set -euo pipefail
die() { echo "run_tests.sh: $*" >&2; exit 2; }

REPO="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="${STAGE:-$HOME/rx-proc-test}"
case "$STAGE" in
    /*) ;; *) die "STAGE must be an absolute path: $STAGE" ;;
esac
case "/$STAGE/" in
    */../*|*/./*) die "STAGE must not contain . or .. elements: $STAGE" ;;
esac
[ "${STAGE%/}" != "${HOME%/}" ] && [ "$STAGE" != "/" ] || die "STAGE must be a dedicated directory, not $STAGE"

if [ -n "${GHIDRA_INSTALL_DIR:-}" ]; then
    props="$GHIDRA_INSTALL_DIR/Ghidra/application.properties"
    [ -f "$props" ] || die "not a Ghidra installation: $GHIDRA_INSTALL_DIR"
    GHIDRA_VERSION=$(sed -n 's/^application.version=//p' "$props")
    GHIDRA_RELEASE=$(sed -n 's/^application.release.name=//p' "$props")
    run_ghidra() { JAVA_TOOL_OPTIONS="-XX:-UsePerfData -Dapplication.settingsdir=$STAGE/ext/config" "$GHIDRA_INSTALL_DIR/support/$1" "${@:2}"; }
else
    GHIDRA_FLATPAK="${GHIDRA_FLATPAK:-org.ghidra_sre.Ghidra}"
    GHIDRA_VERSION="${GHIDRA_VERSION:-12.1.3}"
    GHIDRA_RELEASE="${GHIDRA_RELEASE:-FLATPAK}"
    case "$STAGE/" in
        "$HOME"/*) ;; *) die "with the Flatpak, STAGE must be under \$HOME (the sandbox only sees \$HOME): $STAGE" ;;
    esac
    case "$STAGE" in
        */.*) die "with the Flatpak, STAGE must not contain '.'-prefixed path elements: $STAGE" ;;
    esac
    run_ghidra() { flatpak run --env=JAVA_TOOL_OPTIONS="-XX:-UsePerfData -Dapplication.settingsdir=$STAGE/ext/config" --command="/app/lib/ghidra/support/$1" "$GHIDRA_FLATPAK" "${@:2}"; }
fi

if [ $# -gt 0 ]; then
    VECTORS=()
    for v in "$@"; do VECTORS+=("$(cd "$(dirname "$v")" && pwd)/$(basename "$v")"); done
else
    VECTORS=("$REPO"/test/vectors/*.vec)
fi

EXT="$STAGE/ext/config/ghidra/ghidra_${GHIDRA_VERSION}_${GHIDRA_RELEASE}/Extensions/RX62T"
# only remove what this script creates; STAGE itself may be a directory the user chose
rm -rf "$STAGE/ext" "$STAGE/proj" "$STAGE/zero.bin" "$STAGE"/run-*.log "$STAGE"/sleigh-*.log
mkdir -p "$EXT/data/languages" "$STAGE/proj"
cp "$REPO"/data/languages/*.{ldefs,pspec,cspec,opinion,slaspec,sinc} "$EXT/data/languages/"
cp "$REPO/Module.manifest" "$EXT/"
printf 'name=RX62T\ndescription=RX62T test staging\nauthor=test\ncreatedOn=\nversion=%s\n' "$GHIDRA_VERSION" > "$EXT/extension.properties"

for spec in "$EXT"/data/languages/*.slaspec; do
    if ! run_ghidra sleigh "$spec" "${spec%.slaspec}.sla" > "$STAGE/sleigh-$(basename "$spec").log" 2>&1; then
        echo "SLEIGH COMPILE FAILED: $(basename "$spec")"; grep -iE 'error|line [0-9]+' "$STAGE/sleigh-$(basename "$spec").log" | head -20
        exit 2
    fi
done

head -c 65536 /dev/zero > "$STAGE/zero.bin"
mapfile -t IDS < <(grep -oE 'id="[^"]+"' "$REPO/data/languages/rx62t.ldefs" | grep -v 'id="default"' | sed -E 's/id="(.*)"/\1/')

total_fail=0; total_pass=0; n=0
for id in "${IDS[@]}"; do
    n=$((n + 1))
    log="$STAGE/run-$n.log"
    run_ghidra analyzeHeadless "$STAGE/proj" "p$n" \
        -import "$STAGE/zero.bin" -loader BinaryLoader -loader-baseAddr 0 -processor "$id" \
        -noanalysis -deleteProject -scriptPath "$REPO/test/ghidra_scripts" \
        -postScript RxVectorTest.java "${VECTORS[@]}" > "$log" 2>&1 || true
    grep -oE 'RXTEST (FAIL|SUMMARY).*' "$log" | sed "s/^/[$id] /" || true
    summary=$(grep -oE 'RXTEST SUMMARY [a-z]+ pass=[0-9]+ fail=[0-9]+' "$log" | tail -1 || true)
    if [ -z "$summary" ]; then
        echo "[$id] NO SUMMARY - language failed to load or script crashed (see $log)"
        grep -E 'ERROR|Exception' "$log" | head -10
        total_fail=$((total_fail + 1)); continue
    fi
    p=$(sed -E 's/.*pass=([0-9]+).*/\1/' <<<"$summary"); f=$(sed -E 's/.*fail=([0-9]+).*/\1/' <<<"$summary")
    total_pass=$((total_pass + p)); total_fail=$((total_fail + f))
done

echo "RXTEST TOTAL pass=$total_pass fail=$total_fail (languages: ${IDS[*]})"
[ "$total_fail" -eq 0 ]
