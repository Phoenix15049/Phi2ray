#!/bin/sh
# Downloads the Linux cores into src-tauri/core and checks them against SHA256SUMS.linux. Versions
# come from XRAY_VERSION and SING_BOX_VERSION, or the ones below.
set -eu

xray_version="${XRAY_VERSION:-26.10.21}"
sing_box_version="${SING_BOX_VERSION:-1.14.4}"
core="$(cd "$(dirname "$0")/../src-tauri/core" && pwd)"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 -o "$tmp/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/v$xray_version/Xray-linux-64.zip"
curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 -o "$tmp/sing-box.tar.gz" "https://github.com/SagerNet/sing-box/releases/download/v$sing_box_version/sing-box-$sing_box_version-linux-amd64.tar.gz"

for name in xray geoip.dat geosite.dat; do
    unzip -p "$tmp/xray.zip" "$name" > "$tmp/$name"
done
for name in sing-box libcronet.so; do
    tar -xzOf "$tmp/sing-box.tar.gz" -- "sing-box-$sing_box_version-linux-amd64/$name" > "$tmp/$name"
done

cd "$tmp"
sha256sum -c "$core/SHA256SUMS.linux"
cp xray sing-box libcronet.so geoip.dat geosite.dat "$core/"
chmod 755 "$core/xray" "$core/sing-box"
chmod 644 "$core/libcronet.so" "$core/geoip.dat" "$core/geosite.dat"
