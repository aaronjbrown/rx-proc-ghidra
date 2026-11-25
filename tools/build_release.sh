#!/usr/bin/env bash
# Build the RX62T extension zip for one Ghidra version, for installing with
# File > Install Extensions:
#
#   dist/ghidra_<version>_PUBLIC_<yyyymmdd>_RX62T.zip
#     RX62T/extension.properties   name=RX62T, version=<Ghidra version>
#     RX62T/Module.manifest
#     RX62T/data/                  SLEIGH sources and the compiled .sla files
#     RX62T/ghidra_scripts/
#     RX62T/README.md
#
# By default the zip holds the language files and ghidra_scripts/: it deliberately omits
# lib/RX62T.jar (the RX62T Raw Binary loader and the analyzer) and src/. The upstream project
# (Tim---/rx-proc-ghidra, based on James Chambers' 2019 work) has no LICENSE, so the jar is not
# shipped.
#
# With --with-jar it also builds lib/RX62T.jar from src/main/java of the same revision and names the
# zip ..._RX62T-local.zip. That zip is for installing on your own machine only (the GUI route, with
# no install script); it must not be published or shared.
#
# This script packs only committed files (buildExtension.gradle would zip everything in the project
# directory, untracked files included).
#
# Ghidra accepts an extension only when extension.properties' version equals its own
# application.version; the release name (PUBLIC, FLATPAK, ...) is not checked, so one zip serves
# native and Flatpak installs of the same version.
#
# usage: tools/build_release.sh [--with-jar] [<git revision>]      (default HEAD)
# env:   GHIDRA_INSTALL_DIR  a native Ghidra; uses its support/sleigh and application.version (and,
#                            with --with-jar, its jars and the JDK on JAVA_HOME or PATH)
#        otherwise the Flatpak GHIDRA_FLATPAK (default org.ghidra_sre.Ghidra)
#        BUILD_DIR           scratch directory (default <repo>/build/release; with the Flatpak it must
#                            be under $HOME with no '.'-prefixed elements)
#        DIST_DIR            output directory (default <repo>/dist)
set -euo pipefail
die() { echo "build_release.sh: $*" >&2; exit 2; }
usage() { echo "usage: tools/build_release.sh [--with-jar] [<git revision>]" >&2; exit 2; }

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WITH_JAR= REV=
for arg in "$@"; do
    case "$arg" in
        --with-jar) WITH_JAR=1 ;;
        -*) usage ;;
        *) [ -z "$REV" ] || usage; REV="$arg" ;;
    esac
done
REV="${REV:-HEAD}"
git -C "$REPO" rev-parse --verify -q "$REV^{commit}" > /dev/null || die "not a commit: $REV"
[ -z "$(git -C "$REPO" status --porcelain --untracked-files=no)" ] || [ "$REV" != HEAD ] \
    || echo "build_release.sh: warning: uncommitted changes are not in the zip (it packs $REV)" >&2

if [ -n "${GHIDRA_INSTALL_DIR:-}" ]; then
    props="$GHIDRA_INSTALL_DIR/Ghidra/application.properties"
    [ -f "$props" ] || die "not a Ghidra installation: $GHIDRA_INSTALL_DIR"
    GHIDRA_VERSION=$(sed -n 's/^application.version=//p' "$props")
    sleigh() { "$GHIDRA_INSTALL_DIR/support/sleigh" "$@"; }
else
    GHIDRA_FLATPAK="${GHIDRA_FLATPAK:-org.ghidra_sre.Ghidra}"
    GHIDRA_VERSION=$(flatpak run --command=sed "$GHIDRA_FLATPAK" -n 's/^application.version=//p' \
        /app/lib/ghidra/Ghidra/application.properties)
    sleigh() { flatpak run --env=JAVA_TOOL_OPTIONS=-XX:-UsePerfData --command=/app/lib/ghidra/support/sleigh "$GHIDRA_FLATPAK" "$@"; }
fi
[ -n "$GHIDRA_VERSION" ] || die "could not read the Ghidra version"

BUILD_DIR="${BUILD_DIR:-$REPO/build/release}"
if [ -z "${GHIDRA_INSTALL_DIR:-}" ]; then
    case "$BUILD_DIR/" in "$HOME"/*) ;; *) die "with the Flatpak, BUILD_DIR must be under \$HOME: $BUILD_DIR" ;; esac
    case "${BUILD_DIR#"$HOME"}" in */.*) die "with the Flatpak, BUILD_DIR must not contain '.'-prefixed elements: $BUILD_DIR" ;; esac
fi
STAGE="$BUILD_DIR/RX62T"
rm -rf "${STAGE:?}"
mkdir -p "$STAGE"

DIST_DIR="${DIST_DIR:-$REPO/dist}"
mkdir -p "$DIST_DIR"
DIST_DIR="$(cd "$DIST_DIR" && pwd)"
zipfile="$DIST_DIR/ghidra_${GHIDRA_VERSION}_PUBLIC_$(date +%Y%m%d)_RX62T${WITH_JAR:+-local}.zip"
rm -f "$zipfile"   # a failed build leaves no zip behind

# committed files only
git -C "$REPO" archive --format=tar "$REV" Module.manifest extension.properties README.md data ghidra_scripts \
    | tar -x -C "$STAGE"
sed -i -e 's/@extname@/RX62T/' -e "s/@extversion@/$GHIDRA_VERSION/" "$STAGE/extension.properties"
grep -qx "version=$GHIDRA_VERSION" "$STAGE/extension.properties" || die "extension.properties version not set"

if [ -n "$WITH_JAR" ]; then
    # the jar from the same revision's committed Java sources (build_jar reads <root>/src/main/java)
    rm -rf "$BUILD_DIR/jar-src" "$BUILD_DIR/RX62T.jar"
    mkdir -p "$BUILD_DIR/jar-src" "$STAGE/lib"
    git -C "$REPO" archive --format=tar "$REV" src/main/java | tar -x -C "$BUILD_DIR/jar-src"
    # shellcheck source=java_env.sh
    . "$REPO/tools/java_env.sh"
    build_jar "$BUILD_DIR/jar-src" "$BUILD_DIR/RX62T.jar" > "$BUILD_DIR/jar.log" 2>&1 \
        || { head -20 "$BUILD_DIR/jar.log" >&2; die "jar build failed for $REV; see $BUILD_DIR/jar.log"; }
    unzip -l "$BUILD_DIR/RX62T.jar" 2> /dev/null | grep -q 'rx62t/RX62TLoader.class' \
        || die "jar has no rx62t/RX62TLoader.class"
    mv "$BUILD_DIR/RX62T.jar" "$STAGE/lib/RX62T.jar"
    rm -rf "$BUILD_DIR/jar-src" "$BUILD_DIR/jar.log"
fi

for spec in "$STAGE"/data/languages/*.slaspec; do
    log="$BUILD_DIR/$(basename "$spec" .slaspec).sleigh.log"
    sleigh "$spec" "${spec%.slaspec}.sla" > "$log" 2>&1 \
        || { grep -iE 'error|line [0-9]+' "$log" | head -20 >&2; die "SLEIGH compile failed for $(basename "$spec"); see $log"; }
    rm -f "$log"
done

(cd "$BUILD_DIR" && zip -q -r -X "$zipfile" RX62T)
rm -rf "${STAGE:?}"
echo "built $zipfile ($(git -C "$REPO" rev-parse --short "$REV"), Ghidra $GHIDRA_VERSION)"
unzip -l "$zipfile"
[ -z "$WITH_JAR" ] || echo "build_release.sh: NOTICE: $zipfile contains lib/RX62T.jar. Upstream states no licence:" \
    "install it on your own machine only; do not publish or share it." >&2
