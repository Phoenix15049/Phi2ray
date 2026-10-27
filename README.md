<div align="center">

<img src="docs/logo.svg" width="96" alt="Phi2ray logo" />

# Phi2ray

**A small, careful Xray client for Windows.**
One button to connect, a real kill switch, and settings you can actually understand.

[![Latest release](https://img.shields.io/github/v/release/YOUR_GITHUB_USERNAME/Phi2ray?label=release&color=6c5cf6)](https://github.com/YOUR_GITHUB_USERNAME/Phi2ray/releases/latest)
![Windows 10 / 11](https://img.shields.io/badge/Windows-10%20%7C%2011-1fb6d0)
[![License: MIT](https://img.shields.io/badge/license-MIT-2ee6a6)](LICENSE)

[Download](https://github.com/YOUR_GITHUB_USERNAME/Phi2ray/releases/latest) · [فارسی](README.fa.md)

<br />

<img src="docs/screenshot-dark.jpg" width="280" alt="Phi2ray connected, dark theme" />
&nbsp;
<img src="docs/screenshot-light.jpg" width="280" alt="Phi2ray connected, light theme" />
&nbsp;
<img src="docs/screenshot-fa.jpg" width="280" alt="Phi2ray in Persian" />

</div>

---

## Why another client?

I wanted something for myself that does a few things well. The clients I tried were either
full of switches I didn't understand, or quietly did unsafe things: a SOCKS port open on
`1080` for every app on the machine to find, DNS going straight to the ISP, the real network
leaking for a few seconds every time the connection dropped.

Phi2ray is the result. It's built on [Xray-core](https://github.com/XTLS/Xray-core) for the
protocols and [sing-box](https://github.com/SagerNet/sing-box) for the system-wide VPN adapter,
with a small Rust backend that ties them together and keeps an eye on them. The whole app is a
single `.exe` of about 45 MB, with both cores inside.

## What it does

**Connecting**

- Paste `vless://`, `vmess://`, `trojan://` or `ss://` links, or a base64 list. REALITY, XHTTP,
  WebSocket, gRPC, HTTPUpgrade and TLS are all supported.
- Subscriptions get their own tab, update on their own, and show how much traffic you've used
  and how many days are left (when the provider reports it).
- Group your own servers into tabs, test them all at once with a real request through each
  server (not a TCP ping, which lies), and sort by delay.
- Three modes: **VPN** (the whole system, through a virtual adapter), **System proxy**, or
  **Proxy only** (local ports for apps you set up yourself).

**Staying private**

- **Kill switch**, built on the Windows Filtering Platform. While it's on, nothing reaches the
  internet except through the tunnel, even while reconnecting. If Phi2ray crashes, Windows
  removes the rules by itself, so you never get locked out.
- **Auto-reconnect** that doesn't drop the tunnel. If a core dies or traffic stops, only the
  broken part restarts; your traffic waits instead of leaking.
- DNS goes through the tunnel over DoH. You can pick from Cloudflare, Google, Quad9, AdGuard,
  Mullvad and others, and test which one answers fastest from where you are.
- Local proxy ports are random, and SOCKS always needs a username and password.
- After connecting, the app checks that traffic really flows and shows the IP and country that
  websites see.

**Everyday use**

- **Split tunnel**: choose apps (Telegram, games, anything running) and sites that skip the VPN,
  or flip it around so only they use it.
- Live upload and download speed, plus totals for the session.
- Lives in the tray; minimizing hides it there, and closing while connected asks first.
- Dark and light themes, English and Persian (right-to-left).

## Getting started

1. Download `Phi2ray.exe` from the [latest release](https://github.com/YOUR_GITHUB_USERNAME/Phi2ray/releases/latest).
2. Run it. Windows will ask for administrator rights: VPN mode and the kill switch need them to
   create the network adapter and firewall rules.
3. Click **Add**, paste a link or a subscription URL, and press the power button.

That's it. Everything else in Settings is optional.

> **Windows SmartScreen** may warn about an "unrecognized app" because the exe isn't code-signed
> yet. Choose *More info → Run anyway*. You can check the file against the SHA-256 published with
> each release.

Phi2ray needs the Microsoft Edge WebView2 runtime, which comes with Windows 10 and 11 by default.

## How it works

```
 apps ──► Phi2ray VPN adapter (sing-box) ──► Xray ──► your server ──► internet
                    │                          │
                    └─ DNS over HTTPS ─────────┘
```

- **sing-box** only owns the virtual adapter, the routes and DNS. Every connection is handed to
  Xray's local SOCKS port, so every Xray transport works in VPN mode too.
- **Xray** connects to your server. Its own connection is routed around the tunnel at the OS
  level, so it can never loop back into it.
- The **kill switch** is a set of firewall filters that allow only the tunnel, the two cores,
  your local network (if you want) and DHCP.
- Configs are passed to the cores over stdin, so your server credentials are never written to
  disk in plain text. Saved servers and settings are encrypted with your Windows account (DPAPI).
- The bundled cores are unpacked to `C:\ProgramData\Phi2ray`, a folder only administrators can
  write to, and each one is checked against the hash recorded at build time before it runs.

There's no telemetry and no update check. The only requests Phi2ray makes on its own are the
connection health check and the subscription updates you set up.

## Building from source

You'll need [Rust](https://rustup.rs), [Node.js](https://nodejs.org) 20+, and the Visual Studio
C++ build tools.

```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/Phi2ray.git
cd Phi2ray
npm install
```

Then put the cores in `src-tauri/core/` (see [the note there](src-tauri/core/README.md)):
`xray.exe`, `geoip.dat` and `geosite.dat` from the
[Xray-core releases](https://github.com/XTLS/Xray-core/releases) (`Xray-windows-64.zip`), and
`sing-box.exe` from the [sing-box releases](https://github.com/SagerNet/sing-box/releases)
(`sing-box-<version>-windows-amd64.zip`).

```bash
# Run in development (from a terminal opened as administrator, for VPN mode)
npm run tauri dev

# Build the single-file release: src-tauri/target/release/phi2ray.exe
npm run build:exe
```

`npm run dev` on its own opens the interface in a browser with fake data, which is handy for
working on the UI without touching your network.

<details>
<summary>Project layout</summary>

```
src/                    React interface
src-tauri/src/
  connection.rs         connect, disconnect, and the supervisor that keeps the link alive
  firewall.rs           the kill switch (Windows Filtering Platform)
  config.rs, tun.rs     Xray and sing-box configs
  split.rs              split tunnel rules
  parser.rs             share links and subscriptions
  subscription.rs       downloading and merging subscriptions
  cores.rs              unpacking the bundled cores safely
src-tauri/core/         Xray and sing-box binaries (not in git)
```
</details>

## Questions

**Google shows my location as Iran, but other sites show the server's country.**
That's almost always Google's own location database. It learns where IPs are from phones and
Wi-Fi behind them, and many VPN servers used from Iran get tagged that way. If
[ipleak.net](https://ipleak.net) and [browserleaks.com/webrtc](https://browserleaks.com/webrtc)
show no Iranian IP or DNS server, nothing is leaking.

**It says "Connected" but nothing loads.**
The status turns orange and says "No internet" when traffic isn't getting through. Set the log
level to *Info* in Settings, reconnect, and look at the Logs: the reason is usually right there.

**Split tunnelling for apps doesn't work in System proxy mode.**
Right, only VPN mode can tell which app a connection comes from. Sites work in every mode.

**Some VLESS configs without TLS are rejected.**
Recent Xray versions refuse unencrypted VLESS unless the server is on a private network. That's
an Xray safety rule, not a Phi2ray one.

## Credits

Phi2ray stands on the shoulders of [Xray-core](https://github.com/XTLS/Xray-core) (MPL-2.0),
[sing-box](https://github.com/SagerNet/sing-box) (GPL-3.0) and [Tauri](https://tauri.app).
See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for their licenses and where to get their
source code.

## License

Phi2ray's own code is released under the [MIT License](LICENSE). The bundled cores keep their own
licenses.

Please use it responsibly and within the laws that apply to you.
