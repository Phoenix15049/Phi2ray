#!/bin/sh
# The helper refuses to run if anyone but root could change its folder, so this makes sure of it
# whatever the packaging tool did.
set -e
chown -R root:root /usr/lib/phi2ray
chmod 755 /usr/lib/phi2ray /usr/lib/phi2ray/phi2ray-helper /usr/lib/phi2ray/xray /usr/lib/phi2ray/sing-box
chmod 644 /usr/lib/phi2ray/libcronet.so /usr/lib/phi2ray/geoip.dat /usr/lib/phi2ray/geosite.dat
chmod 755 /usr/bin/phi2ray
