#!/usr/bin/env bash
set -euo pipefail

# setup_android_tools.sh - Cross-platform toolchain installer for macOS & Linux
# Installs uber-apk-signer, Frida Gadgets, Android platform-tools, JADX, and il2dump/Il2CppDumper.

SIGNER_VERSION="1.3.0"
SIGNER_SHA256="e1299fd6fcf4da527dd53735b56127e8ea922a321128123b9c32d619bba1d835"
FRIDA_VERSION="17.16.4"
JADX_VERSION="1.5.6"
JADX_SHA256="545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974"

OS="$(uname -s)"
case "$OS" in
    Darwin)
        PLATFORM="darwin"
        DEFAULT_ROOT="$HOME/Library/Application Support/Reforge/tools"
        ;;
    Linux)
        PLATFORM="linux"
        DEFAULT_ROOT="${XDG_DATA_HOME:-$HOME/.local/share}/Reforge/tools"
        ;;
    *)
        echo "[!] Unsupported operating system: $OS"
        exit 1
        ;;
esac

INSTALL_ROOT="${REFORGE_TOOLS_DIR:-$DEFAULT_ROOT}"

echo "[*] Setting up Reforge Android tools in: $INSTALL_ROOT"
mkdir -p "$INSTALL_ROOT"

# Helper for SHA256 verification
verify_sha256() {
    local file="$1"
    local expected="$2"
    local actual
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$file" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$file" | awk '{print $1}')"
    else
        echo "[!] No sha256sum or shasum found."
        return 1
    fi
    if [[ "$actual" != "$expected" ]]; then
        echo "[!] Checksum verification failed for $file"
        echo "    Expected: $expected"
        echo "    Actual:   $actual"
        return 1
    fi
}

download_verified() {
    local url="$1"
    local dest="$2"
    local expected_hash="$3"

    if [[ -f "$dest" ]] && verify_sha256 "$dest" "$expected_hash" 2>/dev/null; then
        echo "[+] Cached: $(basename "$dest")"
        return 0
    fi

    echo "[*] Downloading: $url"
    curl -fsSL "$url" -o "$dest.tmp"
    verify_sha256 "$dest.tmp" "$expected_hash"
    mv "$dest.tmp" "$dest"
    echo "[+] Verified: $(basename "$dest")"
}

# 1. uber-apk-signer
SIGNER_DIR="$INSTALL_ROOT/uber-apk-signer/$SIGNER_VERSION"
mkdir -p "$SIGNER_DIR"
SIGNER_JAR="$SIGNER_DIR/uber-apk-signer-$SIGNER_VERSION.jar"
download_verified \
    "https://github.com/patrickfav/uber-apk-signer/releases/download/v$SIGNER_VERSION/uber-apk-signer-$SIGNER_VERSION.jar" \
    "$SIGNER_JAR" \
    "$SIGNER_SHA256"

# 2. Frida Gadget libraries
GADGET_DIR="$INSTALL_ROOT/frida-gadget/$FRIDA_VERSION"
mkdir -p "$GADGET_DIR"

declare -A GADGETS=(
    ["frida-gadget-17.16.4-android-arm.so.xz"]="1b19ce187c15d9892d4e737417a1b2a2f6f34ed11e105f1c28fd6b4e3df144a2"
    ["frida-gadget-17.16.4-android-arm64.so.xz"]="b1775f01dcd1224d16815b777c3df61fd12908411b24370e39dcf954dc855fcc"
    ["frida-gadget-17.16.4-android-x86.so.xz"]="95c1598baf82906dc901f46658aa1a924705260fcec3a964c656a6b851e42d74"
    ["frida-gadget-17.16.4-android-x86_64.so.xz"]="0c4aad82c88660bda9ae2f7c7fe30b4820fd7ba6ae7b4b340eb59e29a43622de"
)

for gadget in "${!GADGETS[@]}"; do
    download_verified \
        "https://github.com/frida/frida/releases/download/$FRIDA_VERSION/$gadget" \
        "$GADGET_DIR/$gadget" \
        "${GADGETS[$gadget]}"
done

# 3. Android Platform-Tools (adb)
PLATFORM_DIR="$INSTALL_ROOT/platform-tools"
if [[ ! -x "$PLATFORM_DIR/adb" ]]; then
    echo "[*] Downloading Android platform-tools for $PLATFORM..."
    TMP_ZIP="/tmp/platform-tools-$PLATFORM.zip"
    curl -fsSL "https://dl.google.com/android/repository/platform-tools-latest-$PLATFORM.zip" -o "$TMP_ZIP"
    unzip -q -o "$TMP_ZIP" -d "$INSTALL_ROOT"
    rm -f "$TMP_ZIP"
    echo "[+] Extracted platform-tools (adb)"
else
    echo "[+] Cached: platform-tools (adb)"
fi

# 4. JADX Decompiler
JADX_DIR="$INSTALL_ROOT/jadx/$JADX_VERSION"
if [[ ! -x "$JADX_DIR/bin/jadx" ]]; then
    TMP_JADX="/tmp/jadx-$JADX_VERSION.zip"
    download_verified \
        "https://github.com/skylot/jadx/releases/download/v$JADX_VERSION/jadx-$JADX_VERSION.zip" \
        "$TMP_JADX" \
        "$JADX_SHA256"
    mkdir -p "$JADX_DIR"
    unzip -q -o "$TMP_JADX" -d "$JADX_DIR"
    rm -f "$TMP_JADX"
    chmod +x "$JADX_DIR/bin/jadx" || true
    echo "[+] Extracted JADX"
else
    echo "[+] Cached: JADX $JADX_VERSION"
fi

# 5. Check il2dump / Il2CppDumper
echo ""
if command -v il2dump >/dev/null 2>&1 || [[ -x "$HOME/.cargo/bin/il2dump" ]]; then
    echo "[+] il2dump is installed and available."
else
    echo "[i] Optional Unity IL2CPP dumper: install via Cargo: 'cargo install il2dump'"
fi

echo ""
echo "[+] All Android tools successfully provisioned at $INSTALL_ROOT"
echo "[*] Run 'reforge doctor' to verify readiness."
