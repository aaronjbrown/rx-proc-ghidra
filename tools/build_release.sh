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
# Why not `gradle buildExtension` (support/buildExtension.gradle): that route works (in the Flatpak
# the gradlew wrapper refuses non-PUBLIC builds, but GradleWrapperMain runs), yet compileJava fails
# against Ghidra 12: src/main/java/rx62t holds the 2019 GhidraDev template stubs (a loader that
# returns no load specs, an analyzer that never enables), written for the Ghidra 9 Loader API.
# They contribute nothing, so this script builds a languages-only extension without lib/RX62T.jar
# and leaves the Java sources as upstream has them. buildExtension.gradle also zips everything in
# the project directory, untracked files included; this script packs only committed files.
#
# Ghidra accepts an extension only when extension.properties' version equals its own
# application.version; the release name (PUBLIC, FLATPAK, ...) is not checked, so one zip serves
# native and Flatpak installs of the same version.
#
# usage: tools/build_release.sh [<git revision>]      (default HEAD)
# env:   GHIDRA_INSTALL_DIR  a native Ghidra; uses its support/sleigh and application.version
#        otherwise the Flatpak GHIDRA_FLATPAK (default org.ghidra_sre.Ghidra)
#        BUILD_DIR           scratch directory (default <repo>/build/release; with the Flatpak it must
#                            be under $HOME with no '.'-prefixed elements)
set -euo pipefail
die() { echo "build_release.sh: $*" >&2; exit 2; }

REPO="$(cd "$(dirname "$0")/.." && pwd)"
REV="${1:-HEAD}"
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

# committed files only
git -C "$REPO" archive --format=tar "$REV" Module.manifest extension.properties README.md data ghidra_scripts \
    | tar -x -C "$STAGE"
sed -i -e 's/@extname@/RX62T/' -e "s/@extversion@/$GHIDRA_VERSION/" "$STAGE/extension.properties"
grep -qx "version=$GHIDRA_VERSION" "$STAGE/extension.properties" || die "extension.properties version not set"

for spec in "$STAGE"/data/languages/*.slaspec; do
    log="$BUILD_DIR/$(basename "$spec" .slaspec).sleigh.log"
    sleigh "$spec" "${spec%.slaspec}.sla" > "$log" 2>&1 \
        || { grep -iE 'error|line [0-9]+' "$log" | head -20 >&2; die "SLEIGH compile failed for $(basename "$spec"); see $log"; }
    rm -f "$log"
done

mkdir -p "$REPO/dist"
zipfile="$REPO/dist/ghidra_${GHIDRA_VERSION}_PUBLIC_$(date +%Y%m%d)_RX62T.zip"
rm -f "$zipfile"
(cd "$BUILD_DIR" && zip -q -r -X "$zipfile" RX62T)
rm -rf "${STAGE:?}"
echo "built $zipfile ($(git -C "$REPO" rev-parse --short "$REV"), Ghidra $GHIDRA_VERSION)"
unzip -l "$zipfile"
