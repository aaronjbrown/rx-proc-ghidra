#!/usr/bin/env bash
# Install the RX language files from an rx-proc-ghidra checkout into an already installed RX62T
# Ghidra extension, compiling the .sla files with Ghidra's own SLEIGH compiler. Use it to try
# source changes without building a release zip. Quit Ghidra before running it.
#
# The current data/languages directory is backed up first, to $BACKUP_ROOT, never inside the
# extension. If a SLEIGH compile fails, the backup is restored.
#
# usage: tools/install_extension.sh [--native|--flatpak] [<checkout>]
#        <checkout> defaults to the repository containing this script.
# env:   GHIDRA_INSTALL_DIR  a native Ghidra installation (selects --native by default)
#        GHIDRA_FLATPAK      Flatpak app id (default org.ghidra_sre.Ghidra)
#        GHIDRA_VERSION      Ghidra version of the user settings dir (default 12.1.3)
#        EXT                 the extension directory (overrides the defaults below)
#                            native:  ~/.config/ghidra/ghidra_<version>_PUBLIC/Extensions/RX62T
#                            flatpak: ~/.var/app/<app id>/config/ghidra/ghidra_<version>_FLATPAK/Extensions/RX62T
#        BACKUP_ROOT         where backups go (default ~/ghidra_extension_backups)
set -euo pipefail
die() { echo "install_extension.sh: $*" >&2; exit 2; }

MODE=
case "${1:-}" in
    --native) MODE=native; shift ;;
    --flatpak) MODE=flatpak; shift ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    -*) die "unknown option: $1" ;;
esac
[ -n "$MODE" ] || { [ -n "${GHIDRA_INSTALL_DIR:-}" ] && MODE=native || MODE=flatpak; }

SRC="${1:-$(dirname "$0")/..}"
[ -d "$SRC" ] || die "no such directory: $SRC"
SRC="$(cd "$SRC" && pwd)"
[ -f "$SRC/data/languages/rx62t.ldefs" ] || die "not an rx-proc-ghidra checkout: $SRC"

GHIDRA_VERSION="${GHIDRA_VERSION:-12.1.3}"
GHIDRA_FLATPAK="${GHIDRA_FLATPAK:-org.ghidra_sre.Ghidra}"
if [ "$MODE" = native ]; then
    [ -n "${GHIDRA_INSTALL_DIR:-}" ] || die "--native needs GHIDRA_INSTALL_DIR"
    [ -x "$GHIDRA_INSTALL_DIR/support/sleigh" ] || die "no support/sleigh in GHIDRA_INSTALL_DIR: $GHIDRA_INSTALL_DIR"
    EXT="${EXT:-$HOME/.config/ghidra/ghidra_${GHIDRA_VERSION}_PUBLIC/Extensions/RX62T}"
    sleigh() { "$GHIDRA_INSTALL_DIR/support/sleigh" "$@"; }
else
    command -v flatpak > /dev/null || die "flatpak not found (set GHIDRA_INSTALL_DIR for a native Ghidra)"
    EXT="${EXT:-$HOME/.var/app/$GHIDRA_FLATPAK/config/ghidra/ghidra_${GHIDRA_VERSION}_FLATPAK/Extensions/RX62T}"
    case "$EXT" in "$HOME"/*) ;; *) die "with the Flatpak, EXT must be under \$HOME (the sandbox only sees \$HOME): $EXT" ;; esac
    sleigh() { flatpak run --env=JAVA_TOOL_OPTIONS=-XX:-UsePerfData --command=/app/lib/ghidra/support/sleigh "$GHIDRA_FLATPAK" "$@"; }
fi
LANG_DIR="$EXT/data/languages"

# Ghidra reads the language files at startup and holds them; replacing them under a running Ghidra
# gives a mix of old and new definitions.
RUNNING_CHECK="${GHIDRA_RUNNING_CHECK_CMD:-ps -eo args}"
procs="$($RUNNING_CHECK 2> /dev/null)" || die "cannot check whether Ghidra is running ($RUNNING_CHECK failed)"
if grep -qE '[gG]hidraRun' <<< "$procs"; then
    die "Ghidra appears to be running; quit Ghidra and run this again"
fi

[ -d "$LANG_DIR" ] || die "no RX62T extension at $EXT
  install the extension once (File > Install Extensions with the release zip), restart Ghidra, quit it,
  then run this again; or set EXT to the extension directory"

# Keep backups OUTSIDE the extension: Ghidra loads every .ldefs under Extensions/RX62T/data/, so a
# backup there defines the languages a second time ("previously defined") and the old definition
# can win.
BACKUP_ROOT="${BACKUP_ROOT:-$HOME/ghidra_extension_backups}"
case "$BACKUP_ROOT/" in "$EXT"/*) die "BACKUP_ROOT must be outside the extension: $BACKUP_ROOT" ;; esac
mkdir -p "$BACKUP_ROOT"
backup="$BACKUP_ROOT/$(basename "$EXT")-languages.backup-$(date +%Y%m%d-%H%M%S)"
[ -e "$backup" ] && backup="$backup-$$"
cp -a "$LANG_DIR" "$backup"
echo "backed up $LANG_DIR -> $backup"

done_ok=
restore() {
    [ -n "$done_ok" ] && return
    rm -rf "$LANG_DIR" && cp -a "$backup" "$LANG_DIR" \
        && echo "install failed; restored $LANG_DIR from $backup" >&2 \
        || echo "install failed and the restore failed too; restore by hand from $backup" >&2
}
trap restore EXIT

rm -f "$LANG_DIR"/*.sla
cp "$SRC"/data/languages/*.{ldefs,pspec,cspec,opinion,slaspec,sinc} "$LANG_DIR/"
logdir="$(mktemp -d "$BACKUP_ROOT/sleigh-log.XXXXXX")"
for spec in "$LANG_DIR"/*.slaspec; do
    log="$logdir/$(basename "$spec" .slaspec).sleigh.log"
    if ! sleigh "$spec" "${spec%.slaspec}.sla" > "$log" 2>&1; then
        echo "SLEIGH compile failed for $(basename "$spec"); log kept at $log:" >&2
        grep -iE 'error|line [0-9]+' "$log" | head -20 >&2 || true
        exit 1
    fi
done
rm -rf "$logdir"

{ echo "source: $SRC"; git -C "$SRC" log -1 --format='commit: %h %s (%cd)' 2> /dev/null || true; date; } > "$EXT/INSTALLED_FROM.txt"
done_ok=1
ls "$LANG_DIR"/*.sla
echo "installed. Languages: $(grep -oE 'id="rx62t:[^"]+"' "$LANG_DIR/rx62t.ldefs" | tr '\n' ' ')"
echo "Restart Ghidra to load them."
