#!/usr/bin/env sh
set -e

REPO="fe-dudu/netmon"
BINARY="netmon"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

uname_os=$(uname -s)
uname_arch=$(uname -m)

case "$uname_os" in
  Darwin) os_tag="Darwin" ;;
  Linux) os_tag="Linux" ;;
  *) echo "Unsupported OS: $uname_os" >&2 ; exit 1 ;;
esac

case "$uname_arch" in
  x86_64|amd64) arch_tag="x86_64" ;;
  arm64|aarch64) arch_tag="arm64" ;;
  *) echo "Unsupported architecture: $uname_arch" >&2 ; exit 1 ;;
esac

asset="${BINARY}_${os_tag}_${arch_tag}.tar.gz"
url="https://github.com/${REPO}/releases/latest/download/${asset}"

tmpdir=$(mktemp -d 2>/dev/null || mktemp -d -t netmon)
trap 'rm -rf "$tmpdir"' EXIT

if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
  echo "Need curl or wget to download binaries." >&2
  exit 1
fi

printf "Downloading %s...\n" "$asset"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$url" -o "$tmpdir/$asset"
else
  wget -qO "$tmpdir/$asset" "$url"
fi

if [ ! -s "$tmpdir/$asset" ]; then
  echo "Binary not available for this platform: ${os_tag}_${arch_tag}" >&2
  echo "Please check available releases at: https://github.com/${REPO}/releases" >&2
  exit 1
fi

printf "Extracting %s...\n" "$asset"
tar -xzf "$tmpdir/$asset" -C "$tmpdir"

# Find the binary file (could be netmon, netmon_darwin_arm64, netmon_linux_x86_64, etc.)
binary_file=$(find "$tmpdir" -type f -name "netmon*" ! -name "*.tar.gz" | head -n 1)

if [ -z "$binary_file" ] || [ ! -f "$binary_file" ]; then
  echo "Failed to extract binary from $asset" >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
out_path="$INSTALL_DIR/${BINARY}"

if [ ! -w "$INSTALL_DIR" ]; then
  echo "Elevated permissions may be required to write to $INSTALL_DIR" >&2
  if command -v sudo >/dev/null 2>&1; then
    sudo install -m 755 "$binary_file" "$out_path"
  else
    install -m 755 "$binary_file" "$out_path"
  fi
else
  install -m 755 "$binary_file" "$out_path"
fi

printf "Installed %s to %s\n" "$BINARY" "$out_path"
printf "\nRun with: sudo %s\n" "$BINARY"
