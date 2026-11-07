#!/bin/sh
# Downloads the Linux cores into src-tauri/core and checks them against SHA256SUMS.linux. Versions
# come from XRAY_VERSION and SING_BOX_VERSION, or the ones below.
set -eu

xray_version="${XRAY_VERSION:-26.10.21}"
sing_box_version="${SING_BOX_VERSION:-1.14.4}"
core="$(cd "$(dirname "$0")/../src-tauri/core" && pwd)"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/v$xray_version/Xray-linux-64.zip"
curl -fsSL -o "$tmp/sing-box.tar.gz" "https://github.com/SagerNet/sing-box/releases/download/v$sing_box_version/sing-box-$sing_box_version-linux-amd64.tar.gz"

unzip -qo "$tmp/xray.zip" xray geoip.dat geosite.dat -d "$core"
tar -xzf "$tmp/sing-box.tar.gz" -C "$tmp"
cp "$tmp/sing-box-$sing_box_version-linux-amd64/sing-box" "$tmp/sing-box-$sing_box_version-linux-amd64/libcronet.so" "$core/"

cd "$core"
sha256sum -c SHA256SUMS.linux
chmod 755 xray sing-box
chmod 644 geoip.dat geosite.dat libcronet.so
