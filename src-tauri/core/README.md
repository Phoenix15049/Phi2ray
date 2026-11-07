# Cores

## Linux

`scripts/get-linux-cores.sh` downloads `xray`, `sing-box`, `libcronet.so`, `geoip.dat` and
`geosite.dat` into this folder and checks them against `SHA256SUMS.linux`.

## Windows

Put these files in this folder:

From Xray-core (https://github.com/XTLS/Xray-core/releases, `Xray-windows-64.zip`):

- `xray.exe`
- `geoip.dat`, `geosite.dat` (needed for the "Iranian sites direct" rule)

From sing-box (https://github.com/SagerNet/sing-box/releases, `sing-box-<version>-windows-amd64.zip`),
needed only for VPN mode:

- `sing-box.exe`

`SHA256SUMS` pins the exact files a release embeds; `npm run build:exe` fails if any file here
doesn't match it. When you update a core, check the new files against the `.dgst` digests on
the official release page first, then update `SHA256SUMS`:

```bash
cd src-tauri/core
sha256sum geoip.dat geosite.dat libcronet.dll sing-box.exe xray.exe > SHA256SUMS
```

The release workflow (`.github/workflows/release.yml`) downloads the cores itself; when you
update them, also update `XRAY_VERSION` and `SING_BOX_VERSION` there and in `linux.yml`, the
defaults in `scripts/get-linux-cores.sh`, and `SHA256SUMS.linux`.

Windows releases always embed the cores (`npm run build:exe`). A release without them would run
cores from a folder normal users can write to, while Phi2ray runs as administrator. On Linux the
packages install them in `/usr/lib/phi2ray`, which only root can change.

For development builds, `xray.exe.sha256` / `sing-box.exe.sha256` next to a core are optional;
if present, Phi2ray refuses to start a core whose hash does not match.
