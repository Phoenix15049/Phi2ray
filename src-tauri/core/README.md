# Cores

Put these files in this folder:

From Xray-core (https://github.com/XTLS/Xray-core/releases, `Xray-windows-64.zip`):

- `xray.exe`
- `geoip.dat`, `geosite.dat` (needed for the "Iranian sites direct" rule)

From sing-box (https://github.com/SagerNet/sing-box/releases, `sing-box-<version>-windows-amd64.zip`),
needed only for VPN mode:

- `sing-box.exe`

Optional: `xray.exe.sha256` / `sing-box.exe.sha256` containing the expected SHA-256.
If present, Phi2ray refuses to start a core whose hash does not match.
