#!/bin/sh
set -e

# ghostenv installer — detects OS/arch and downloads the latest release.
# Usage: curl -sL https://raw.githubusercontent.com/Rituraj003/ghostenv/main/install.sh | sh

REPO="Rituraj003/ghostenv"
INSTALL_DIR="/usr/local/bin"

# Detect OS
OS="$(uname -s)"
case "$OS" in
    Linux)  OS="linux" ;;
    Darwin) OS="darwin" ;;
    *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)  ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *)             echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Get latest version
VERSION="$(curl -sI "https://github.com/$REPO/releases/latest" | grep -i '^location:' | sed 's/.*tag\///' | tr -d '\r\n')"
if [ -z "$VERSION" ]; then
    echo "Could not determine latest version."
    exit 1
fi

FILENAME="ghostenv_${VERSION#v}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/$REPO/releases/download/$VERSION/$FILENAME"

echo "Installing ghostenv $VERSION ($OS/$ARCH)..."

# Download and extract to temp dir
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -sL "$URL" -o "$TMP/$FILENAME"
tar xzf "$TMP/$FILENAME" -C "$TMP"

# Install
if [ -w "$INSTALL_DIR" ]; then
    cp "$TMP/ghostenv" "$INSTALL_DIR/ghostenv"
    [ -f "$TMP/ghostenv-keychain" ] && cp "$TMP/ghostenv-keychain" "$INSTALL_DIR/ghostenv-keychain"
else
    echo "Need sudo to install to $INSTALL_DIR"
    sudo cp "$TMP/ghostenv" "$INSTALL_DIR/ghostenv"
    [ -f "$TMP/ghostenv-keychain" ] && sudo cp "$TMP/ghostenv-keychain" "$INSTALL_DIR/ghostenv-keychain"
fi

chmod +x "$INSTALL_DIR/ghostenv"
[ -f "$INSTALL_DIR/ghostenv-keychain" ] && chmod +x "$INSTALL_DIR/ghostenv-keychain"

echo "ghostenv $VERSION installed to $INSTALL_DIR/ghostenv"
