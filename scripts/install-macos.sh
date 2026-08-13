#!/usr/bin/env bash
set -euo pipefail
repo="Teknesyum/AiScanner"
arch=$(uname -m); rid="osx-x64"; [ "$arch" = "arm64" ] && rid="osx-arm64"
app_dir="$HOME/Applications/AI Scanner.app"
asset_url=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | grep browser_download_url | grep "$rid.tar.gz" | cut -d '"' -f 4 | head -n1)
[ -n "$asset_url" ] || { echo "macOS release asset not found for $arch." >&2; exit 1; }
tmp_dir=$(mktemp -d); trap 'rm -rf "$tmp_dir"' EXIT
curl -fL "$asset_url" -o "$tmp_dir/aiscanner.tar.gz"; mkdir -p "$app_dir/Contents/MacOS" "$app_dir/Contents/Resources"
tar -xzf "$tmp_dir/aiscanner.tar.gz" -C "$app_dir/Contents/MacOS"; chmod +x "$app_dir/Contents/MacOS/AiScanner"
cp "$app_dir/Contents/MacOS/Assets/AiScannerIcon.png" "$app_dir/Contents/Resources/AiScannerIcon.png"
cat > "$app_dir/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleExecutable</key><string>AiScanner</string><key>CFBundleIdentifier</key><string>com.teknesyum.aiscanner</string><key>CFBundleName</key><string>AI Scanner</string><key>CFBundleVersion</key><string>0.3.0</string><key>CFBundlePackageType</key><string>APPL</string><key>NSHighResolutionCapable</key><true/></dict></plist>
EOF
echo "Installed: $app_dir"
open "$app_dir"
