#!/usr/bin/env bash
set -euo pipefail
repo="Teknesyum/AiScanner"
install_dir="${XDG_DATA_HOME:-$HOME/.local/share}/AiScanner"
bin_dir="$HOME/.local/bin"
asset_url=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | grep browser_download_url | grep 'linux-x64.tar.gz' | cut -d '"' -f 4 | head -n1)
[ -n "$asset_url" ] || { echo "Linux x64 release asset not found." >&2; exit 1; }
tmp_dir=$(mktemp -d); trap 'rm -rf "$tmp_dir"' EXIT
curl -fL "$asset_url" -o "$tmp_dir/aiscanner.tar.gz"
mkdir -p "$install_dir" "$bin_dir" "${XDG_DATA_HOME:-$HOME/.local/share}/applications"
tar -xzf "$tmp_dir/aiscanner.tar.gz" -C "$install_dir"
chmod +x "$install_dir/AiScanner"
ln -sf "$install_dir/AiScanner" "$bin_dir/aiscanner"
cat > "${XDG_DATA_HOME:-$HOME/.local/share}/applications/aiscanner.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=AI Scanner
Comment=Process telemetry and AI-assisted threat analysis
Exec=$install_dir/AiScanner
Icon=$install_dir/Assets/AiScannerIcon.png
Terminal=false
Categories=System;Security;
EOF
echo "AI Scanner installed. Run: aiscanner"
if [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; then
  "$install_dir/AiScanner" >/dev/null 2>&1 &
fi
