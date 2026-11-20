# Sourced helper: run the JDK and build against Ghidra, natively or through the Flatpak.
#
#   . tools/java_env.sh
#   jdk <javac|java|jar> args...   run a JDK tool
#   ghidra_classpath               print the ':'-joined Ghidra jars (as buildExtension.gradle uses)
#   build_jar <src_root> <dest_jar>  compile <src_root>/src/main/java/**/*.java and jar them
#
# env:   GHIDRA_INSTALL_DIR  a Ghidra installation; the JDK is $JAVA_HOME/bin or PATH
#        otherwise the Flatpak: GHIDRA_FLATPAK (org.ghidra_sre.Ghidra); JDK at /app/jdk,
#        Ghidra at /app/lib/ghidra. The Flatpak only sees $HOME: paths passed to these functions
#        must be absolute, under $HOME, with no '.'-prefixed elements.

if [ -n "${GHIDRA_INSTALL_DIR:-}" ]; then
    _props="$GHIDRA_INSTALL_DIR/Ghidra/application.properties"
    [ -f "$_props" ] || { echo "java_env.sh: not a Ghidra installation: $GHIDRA_INSTALL_DIR" >&2; return 2; }
    _GHIDRA_DIR="$GHIDRA_INSTALL_DIR"
    jdk() {
        local tool="$1"; shift
        if [ -n "${JAVA_HOME:-}" ]; then "$JAVA_HOME/bin/$tool" "$@"; else "$tool" "$@"; fi
    }
    _jdk_sh() { sh -c "$1"; }
else
    GHIDRA_FLATPAK="${GHIDRA_FLATPAK:-org.ghidra_sre.Ghidra}"
    _GHIDRA_DIR=/app/lib/ghidra
    jdk() {
        local tool="$1"; shift
        flatpak run --command="/app/jdk/bin/$tool" "$GHIDRA_FLATPAK" "$@"
    }
    _jdk_sh() { flatpak run --command=sh "$GHIDRA_FLATPAK" -c "$1"; }
fi

# --release level from application.java.compiler
_java_release() {
    _jdk_sh "sed -n 's/^application.java.compiler=//p' '$_GHIDRA_DIR/Ghidra/application.properties'"
}

ghidra_classpath() {
    _jdk_sh "ls '$_GHIDRA_DIR'/Ghidra/Framework/*/lib/*.jar '$_GHIDRA_DIR'/Ghidra/Features/*/lib/*.jar '$_GHIDRA_DIR'/Ghidra/Debug/*/lib/*.jar '$_GHIDRA_DIR'/Ghidra/Processors/*/lib/*.jar 2>/dev/null" | paste -sd:
}

build_jar() {
    local src_root="$1" dest="$2" release tmp
    release="$(_java_release)"
    [ -n "$release" ] || { echo "build_jar: cannot read application.java.compiler" >&2; return 2; }
    tmp="$dest.classes"
    rm -rf "$tmp"; mkdir -p "$tmp"
    find "$src_root/src/main/java" -name '*.java' | sort > "$tmp.sources"
    jdk javac --release "$release" -proc:none -nowarn -cp "$(ghidra_classpath)" -d "$tmp" @"$tmp.sources" || return 1
    rm -f "$dest"
    jdk jar --create --file "$dest" -C "$tmp" . || return 1
    rm -rf "$tmp" "$tmp.sources"
}
