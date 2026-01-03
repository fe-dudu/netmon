#!/usr/bin/env sh
set -e

REPO="fe-dudu/netmon"
BINARY="netmon"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

uname_os=$(uname -s)
uname_arch=$(uname -m)

case "$uname_os" in
  Darwin) os_tag="darwin" ;;
  Linux) os_tag="linux" ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT) os_tag="win32" ;;
  *) echo "Unsupported OS: $uname_os" >&2 ; exit 1 ;;
esac

case "$uname_arch" in
  x86_64|amd64) arch_tag="x64" ;;
  arm64|aarch64) arch_tag="arm64" ;;
  armv7l|armv7) arch_tag="arm" ;;
  i386|i686|386) arch_tag="ia32" ;;
  *) echo "Unsupported architecture: $uname_arch" >&2 ; exit 1 ;;
esac

ext=""
if [ "$os_tag" = "win32" ]; then
  ext=".exe"
fi

asset="${BINARY}_${os_tag}_${arch_tag}${ext}"
url="https://github.com/${REPO}/releases/latest/download/${asset}"

tmpdir=$(mktemp -d 2>/dev/null || mktemp -d -t netmon)
trap 'rm -rf "$tmpdir"' EXIT

need_downloader=true
download() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2" && need_downloader=false
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$2" "$1" && need_downloader=false
  fi
}

printf "Downloading %s...\n" "$asset"
download "$url" "$tmpdir/$asset" || true

if [ "$need_downloader" = true ]; then
  echo "Need curl or wget to download binaries." >&2
  exit 1
fi

if [ ! -s "$tmpdir/$asset" ]; then
  echo "Binary not available for this platform: ${os_tag}_${arch_tag}" >&2
  echo "Please check available releases at: https://github.com/${REPO}/releases" >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
out_path="$INSTALL_DIR/${BINARY}${ext}"

if [ ! -w "$INSTALL_DIR" ]; then
  echo "Elevated permissions may be required to write to $INSTALL_DIR" >&2
  if command -v sudo >/dev/null 2>&1; then
    sudo install -m 755 "$tmpdir/$asset" "$out_path"
  else
    install -m 755 "$tmpdir/$asset" "$out_path"
  fi
else
  install -m 755 "$tmpdir/$asset" "$out_path"
fi

printf "Installed %s to %s\n" "$BINARY" "$out_path"
printf "\nRun with: sudo %s\n" "$BINARY"
