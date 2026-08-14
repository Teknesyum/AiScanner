#!/usr/bin/env bash
set -euo pipefail
repo="Teknesyum/ProcWitness"
install_dir="${XDG_DATA_HOME:-$HOME/.local/share}/ProcWitness"
bin_dir="$HOME/.local/bin"
asset_url=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | grep browser_download_url | grep 'linux-x64.tar.gz' | cut -d '"' -f 4 | head -n1)
[ -n "$asset_url" ] || { echo "Linux x64 release asset not found." >&2; exit 1; }
tmp_dir=$(mktemp -d); trap 'rm -rf "$tmp_dir"' EXIT
curl -fL "$asset_url" -o "$tmp_dir/procwitness.tar.gz"
mkdir -p "$install_dir" "$bin_dir" "${XDG_DATA_HOME:-$HOME/.local/share}/applications"
tar -xzf "$tmp_dir/procwitness.tar.gz" -C "$install_dir"
chmod +x "$install_dir/ProcWitness"
ln -sf "$install_dir/cli/procwitness" "$bin_dir/procwitness"
cat > "${XDG_DATA_HOME:-$HOME/.local/share}/applications/procwitness.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=ProcWitness
Comment=Process telemetry and AI-assisted threat analysis
Exec=$install_dir/ProcWitness
Icon=$install_dir/Assets/ProcWitnessIcon.png
Terminal=false
Categories=System;Security;
EOF
echo "ProcWitness installed. Run: procwitness"
if [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; then
  "$install_dir/ProcWitness" >/dev/null 2>&1 &
fi
