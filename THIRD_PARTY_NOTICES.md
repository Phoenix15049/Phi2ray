# Third-party notices

The release build of Phi2ray (`Phi2ray.exe`) bundles the following programs unmodified. They run
as separate processes and keep their own licenses. Phi2ray's own code is MIT-licensed.

| Component | Version | License | Source code |
|---|---|---|---|
| [Xray-core](https://github.com/XTLS/Xray-core) | 26.10.21 | [MPL-2.0](https://github.com/XTLS/Xray-core/blob/main/LICENSE) | <https://github.com/XTLS/Xray-core/tree/v26.10.21> |
| [sing-box](https://github.com/SagerNet/sing-box) | 1.14.4 | [GPL-3.0-or-later](https://github.com/SagerNet/sing-box/blob/main/LICENSE) | <https://github.com/SagerNet/sing-box/tree/v1.14.4> |
| geoip.dat / geosite.dat | shipped with Xray-core 26.10.21 | see the Xray-core release | <https://github.com/XTLS/Xray-core/releases/tag/v26.10.21> |

The exact source code for the bundled binaries is available at the links above. If you'd rather
receive it from me, open an issue on this repository and I'll send it.

The application itself is built with [Tauri](https://tauri.app) (MIT / Apache-2.0),
[React](https://react.dev) (MIT) and the Rust and npm packages listed in `src-tauri/Cargo.lock`
and `package-lock.json`, each under its own license.

**Instrument Sans** and **Martian Mono** (the interface's fonts) are under the SIL Open Font
License 1.1. Their license texts are in `src/assets/fonts/`.
