#!/bin/sh
set -e

# Repository info
REPO="dhiraj-rajput/arc"

# Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
  linux)
    if [ "$ARCH" = "x86_64" ]; then
      ASSET="arc-linux-amd64.tar.gz"
    else
      echo "Unsupported Linux architecture: $ARCH"
      exit 1
    fi
    ;;
  darwin)
    if [ "$ARCH" = "x86_64" ]; then
      ASSET="arc-macos-amd64.tar.gz"
    elif [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
      ASSET="arc-macos-arm64.tar.gz"
    else
      echo "Unsupported macOS architecture: $ARCH"
      exit 1
    fi
    ;;
  *)
    echo "Unsupported OS: $OS"
    exit 1
    ;;
esac

URL="https://github.com/$REPO/releases/latest/download/$ASSET"

echo "🌌 Installing arc..."
echo "Detecting environment: OS=$OS, ARCH=$ARCH"
echo "Downloading package from: $URL"

# Create temp dir
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

# Download and extract
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$URL" -o "$TEMP_DIR/arc.tar.gz"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$TEMP_DIR/arc.tar.gz" "$URL"
else
  echo "Error: Neither curl nor wget was found. Please install one of them."
  exit 1
fi

tar -xzf "$TEMP_DIR/arc.tar.gz" -C "$TEMP_DIR"

# Install location detection
# If run with sudo, or user is root, install to /usr/local/bin
if [ "$(id -u)" -eq 0 ]; then
  DEST_DIR="/usr/local/bin"
else
  DEST_DIR="$HOME/.local/bin"
fi

mkdir -p "$DEST_DIR"
mv "$TEMP_DIR/arc" "$DEST_DIR/arc"
chmod +x "$DEST_DIR/arc"

echo "✨ arc has been installed successfully to: $DEST_DIR/arc"

# Check if DEST_DIR is in PATH
case ":$PATH:" in
  *:"$DEST_DIR":*)
    # Already in PATH
    ;;
  *)
    echo "⚠️  Note: '$DEST_DIR' is not in your PATH."
    if [ "$DEST_DIR" = "$HOME/.local/bin" ]; then
      SHELL_CONFIG=""
      if [ -n "$ZSH_VERSION" ] || [ -f "$HOME/.zshrc" ]; then
        SHELL_CONFIG="$HOME/.zshrc"
      elif [ -n "$BASH_VERSION" ] || [ -f "$HOME/.bashrc" ]; then
        SHELL_CONFIG="$HOME/.bashrc"
      else
        SHELL_CONFIG="$HOME/.profile"
      fi

      echo "To add it to your PATH, run:"
      echo "  echo 'export PATH=\"\$PATH:$DEST_DIR\"' >> $SHELL_CONFIG"
      echo "  source $SHELL_CONFIG"
    fi
    ;;
esac

echo "🌌 Run 'arc --help' to get started!"
