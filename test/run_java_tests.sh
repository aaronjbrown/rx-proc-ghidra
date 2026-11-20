#!/usr/bin/env bash
# Build the Java loader/analyzer jar from source and run the dependency-free test mains
# (src/test/java/rx62t/*Test.java). Each prints RXTEST PASS|FAIL lines and an RXTEST SUMMARY.
#
# usage: test/run_java_tests.sh
# env:   GHIDRA_INSTALL_DIR  a Ghidra installation (native JDK); otherwise the Flatpak
#        GHIDRA_FLATPAK (org.ghidra_sre.Ghidra)
#        STAGE  scratch directory (default $HOME/rx-proc-test); only java/ below it is replaced.
#               With the Flatpak it must be under $HOME with no '.'-prefixed elements.
set -euo pipefail
die() { echo "run_java_tests.sh: $*" >&2; exit 2; }

REPO="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="${STAGE:-$HOME/rx-proc-test}"
case "$STAGE" in
    /*) ;; *) die "STAGE must be an absolute path: $STAGE" ;;
esac
case "/$STAGE/" in
    */../*|*/./*) die "STAGE must not contain . or .. elements: $STAGE" ;;
esac
[ "${STAGE%/}" != "${HOME%/}" ] && [ "$STAGE" != "/" ] || die "STAGE must be a dedicated directory, not $STAGE"

if [ -z "${GHIDRA_INSTALL_DIR:-}" ]; then
    case "$STAGE/" in
        "$HOME"/*) ;; *) die "with the Flatpak, STAGE must be under \$HOME (the sandbox only sees \$HOME): $STAGE" ;;
    esac
    case "$STAGE" in
        */.*) die "with the Flatpak, STAGE must not contain '.'-prefixed path elements: $STAGE" ;;
    esac
fi

# shellcheck source=../tools/java_env.sh
. "$REPO/tools/java_env.sh"

OUT="$STAGE/java"
JAR="$OUT/RX62T.jar"
rm -rf "$OUT"; mkdir -p "$OUT"

build_jar "$REPO" "$JAR" || die "jar build failed"

mkdir -p "$OUT/test-classes"
CP="$JAR:$(ghidra_classpath)"
release="$(_java_release)"
jdk javac --release "$release" -proc:none -nowarn -cp "$CP" -d "$OUT/test-classes" "$REPO"/src/test/java/rx62t/*.java \
    || die "test compile failed"

if [ -n "${GHIDRA_INSTALL_DIR:-}" ]; then
    run_java() { jdk java "$@"; }
else
    run_java() { flatpak run --command=/app/jdk/bin/java "$GHIDRA_FLATPAK" "$@"; }
fi

total_pass=0; total_fail=0
for src in "$REPO"/src/test/java/rx62t/*Test.java; do
    cls="rx62t.$(basename "$src" .java)"
    log="$OUT/$cls.log"
    run_java -cp "$OUT/test-classes:$CP" "$cls" > "$log" 2>&1 || true
    grep -E 'RXTEST (FAIL|SKIP)' "$log" || true
    summary=$(grep -oE 'RXTEST SUMMARY [A-Za-z0-9_]+ pass=[0-9]+ fail=[0-9]+' "$log" | tail -1 || true)
    if [ -z "$summary" ]; then
        echo "[$cls] NO SUMMARY - test crashed (see $log)"
        grep -E 'Exception|Error' "$log" | head -10 || true
        total_fail=$((total_fail + 1)); continue
    fi
    total_pass=$((total_pass + $(sed -E 's/.*pass=([0-9]+).*/\1/' <<<"$summary")))
    total_fail=$((total_fail + $(sed -E 's/.*fail=([0-9]+).*/\1/' <<<"$summary")))
done

echo "RXTEST TOTAL pass=$total_pass fail=$total_fail"
[ "$total_fail" -eq 0 ]
