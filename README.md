<div align="center">

<img src="docs/logo.svg" width="96" alt="Phi2ray logo" />

# Phi2ray

**An Xray client for Windows that tries hard not to leak.🐱**

[![Latest release](https://img.shields.io/github/v/release/Phoenix15049/Phi2ray?label=release&color=6c5cf6)](https://github.com/Phoenix15049/Phi2ray/releases/latest)
![Windows 10 / 11](https://img.shields.io/badge/Windows-10%20%7C%2011-1fb6d0)
[![License: MIT](https://img.shields.io/badge/license-MIT-2ee6a6)](LICENSE)

[Download](https://github.com/Phoenix15049/Phi2ray/releases/latest) · [فارسی](README.fa.md)

<br />

<img src="docs/screenshot-dark.jpg" width="280" alt="Phi2ray connected, dark theme" />
&nbsp;
<img src="docs/screenshot-light.jpg" width="280" alt="Phi2ray connected, light theme" />
&nbsp;
<img src="docs/screenshot-fa.jpg" width="280" alt="Phi2ray in Persian" />

</div>

---

## The short version

You paste a link, press the big button, and your whole PC goes through your server. If the
connection drops, your traffic waits for it to come back instead of quietly going out over your
real network. That's most of what Phi2ray is about.

## Why I made it

I use Xray configs every day, and I kept running into the same two problems with the clients
out there. Some had so many options that I was never sure what I'd actually turned on. Others
looked simple but did things I wasn't comfortable with once I looked closer: a SOCKS port sitting
open on `1080` for any program to find, DNS lookups going straight to my ISP, and a few seconds
of leaking every time the connection hiccuped.

So I wrote my own. The heavy lifting is done by [Xray-core](https://github.com/XTLS/Xray-core)
(the protocols) and [sing-box](https://github.com/SagerNet/sing-box) (the system-wide VPN adapter).
Phi2ray is the part in between: a small Rust app that sets them up safely, watches them, and stays
out of your way. It ships as one `.exe`, about 45 MB, with both cores inside.

## What you get

**Connecting**

- Works with `vless://`, `vmess://`, `trojan://` and `ss://` links, plus base64 lists. REALITY,
  XHTTP, WebSocket, gRPC, HTTPUpgrade and plain TLS all work.
- Subscriptions sit in their own tab and refresh by themselves. If your provider shares it, you'll
  see how much data you've used and how many days are left.
- Servers that aren't safe get a small ⚠ next to them: no encryption to the server, or TLS that
  doesn't check the certificate (`allowInsecure`). Subscription links over plain `http://` get a
  warning too, since anyone on the way could read or change them.
- Put your own servers into groups, and test a whole group at once. The test sends a real request
  through each server, so a server that's "up" but not actually working shows as failed instead
  of getting a fake 1 ms.
- Three ways to connect: **VPN** for the whole system, **System proxy** for browsers and apps
  that follow Windows' proxy settings, or **Proxy only** if you'd rather point apps at it yourself.

**Not leaking**

- **Kill switch.** It's a set of Windows firewall rules, not a timer that hopes for the best.
  While it's on, nothing gets out except through the tunnel, including while it reconnects or
  switches servers. If Phi2ray ever crashes, the block stays, so nothing leaks: open Phi2ray
  again to reconnect or unblock. Restarting Windows always clears it too, so you can't end up
  locked out for good. The flip side: it's off from the moment Windows starts until Phi2ray
  does. It's there to catch accidental leaks, not to fight malware already running on your PC.
- **Reconnecting without letting go.** When something breaks, only the broken piece restarts and
  the tunnel stays up. Your apps wait a few seconds; they don't fall back to your real connection.
- **DNS through the tunnel**, over HTTPS. Pick Cloudflare, Google, Quad9, AdGuard, Mullvad or
  another one, and hit *Test* to see which answers fastest from where you are.
- Local proxy ports are random each time and only reachable from this PC. SOCKS always asks for
  a username and password, and in VPN mode there's no HTTP port at all. (In the proxy modes the
  HTTP port has no password, because Windows has no way to hand one to apps.)
- In System proxy mode, Windows' automatic proxy detection (WPAD) and setup scripts are switched
  off while you're connected and put back afterwards, so a fake one on public Wi-Fi can't send
  your browser around the proxy.
- Once connected, it checks that traffic actually gets through and shows the IP and country that
  websites see. If something's wrong you'll know right away, not after five minutes of loading
  spinners.
- **Connection info** (the ⓘ button) shows your exit IP and location as several databases see it,
  plus where the connection enters. If the entry and the exit are different servers, it tells you
  the config goes through a relay or a CDN first. It only runs when you open it, and every lookup
  goes through your server.

**Day to day**

- **Split tunnel.** Let some apps or sites skip the VPN (your bank, a game, a local site), or flip
  it so only the ones you choose use it. You can pick apps straight from what's running. A small
  icon next to the kill switch lock shows when it's on.
- Live download and upload speed, and how much you've used this session.
- Sits in the tray. Minimizing hides it there, and if you close it while connected, it asks first.
  A dot on the tray icon tells you the state at a glance: blue when connected, orange while
  reconnecting, red when the kill switch is holding the internet blocked, none when off.
- Dark and light themes, and a full Persian interface.

## Getting started

1. Grab `Phi2ray-<version>-windows-x64.exe` from the [latest release](https://github.com/Phoenix15049/Phi2ray/releases/latest).
2. Run it. Windows will ask for administrator rights. That's needed to create the VPN adapter
   and the firewall rules, and it's why Phi2ray doesn't run without it.
3. Click **Add**, paste a link or your subscription URL, and press the power button.

That's really all. Everything in Settings has a sensible default, so you only go there if you
want to change something.

> **About the SmartScreen warning:** the exe isn't code-signed yet, so Windows may call it an
> "unrecognized app". Click *More info → Run anyway*. If you want to be sure the file is the one
> I published, compare its SHA-256 with the one in the release notes.

You'll also need the Microsoft Edge WebView2 runtime. It comes with Windows 10 and 11, so you
almost certainly have it already.

## Under the hood

```
 your apps ──► Phi2ray VPN adapter (sing-box) ──► Xray ──► your server ──► internet
                          │                         │
                          └──── DNS over HTTPS ─────┘
```

- **sing-box** only handles the virtual network adapter, routing and DNS. It hands every
  connection to Xray, which means any transport Xray supports also works in VPN mode.
- **Xray** talks to your server. Its own connection to the server is routed around the tunnel by
  Windows itself, so it can't accidentally loop back into it.
- The **kill switch** allows only the tunnel, the two cores (and only as Phi2ray starts them,
  with administrator rights), DHCP, and your local network if you want printers and the router
  to stay reachable. Everything else is blocked.
- Your server details are handed to the cores through stdin and never written to disk as plain
  text. Saved servers and settings are encrypted with your Windows account (DPAPI). That keeps
  them safe if the file is copied somewhere else; programs running as you on this PC can still
  read them, as with any app.
- The cores are unpacked into `C:\Program Files\Phi2ray`, where only administrators can create
  or change anything. Each file is checked against the hash recorded at build time and then kept
  open with writing blocked until Phi2ray exits, so what runs is exactly what was checked. Since
  Phi2ray runs as admin, this stops other programs from swapping a core to get admin rights.
- Before Xray counts as started, Phi2ray checks that its local ports really belong to it, so
  another program can't grab a port first and pose as the proxy.
- Subscriptions are capped at 8 MB and 2000 servers, and a redirect from `https` to `http` is
  refused. Plain `http://` subscriptions don't update by themselves. Error messages never
  include a subscription link or a server's password, so logs are safe to share. The window
  itself never receives your servers' passwords or IDs.
- While connected, subscription updates and the DNS test always go through your server, even
  when the split tunnel would send other traffic directly.
- When DNS answers a filtered server with a fake private address (like `10.10.34.36`), Phi2ray
  ignores it. The last good address of each server is remembered, so reconnecting still works
  when DNS can't be reached.

**What doesn't go through the tunnel**, so there are no surprises:

- Your local network (router, printers, other PCs), while *Bypass local network* is on.
- Apps and sites you exclude with split tunnel, or with *Only via VPN*, everything you didn't list.
- Iranian sites, if you turn that option on.
- Anything addressed to your server's own IP. That's how the tunnel itself gets out; it only
  matters if your server sits behind a CDN address that other sites share.
- *Test* on the server list connects straight to each server, as every client does. It's the
  same connection the server sees when you use it.

There's no telemetry, no analytics and no update check. The only requests Phi2ray makes on its
own are the connection check while you're connected and the subscription updates you added.
Connection info asks ipapi.co, DB-IP, FreeIPAPI and Cloudflare (including where your server is),
but only when you open it, and through your server.

## Building it yourself

You'll need [Rust](https://rustup.rs), [Node.js](https://nodejs.org) 20 or newer, and the Visual
Studio C++ build tools.

```bash
git clone https://github.com/Phoenix15049/Phi2ray.git
cd Phi2ray
npm install
```

The cores aren't in the repo, so download them and drop them into `src-tauri/core/`
([details](src-tauri/core/README.md)):

- `xray.exe`, `geoip.dat` and `geosite.dat` from `Xray-windows-64.zip` on the
  [Xray-core releases page](https://github.com/XTLS/Xray-core/releases)
- `sing-box.exe` from `sing-box-<version>-windows-amd64.zip` on the
  [sing-box releases page](https://github.com/SagerNet/sing-box/releases)

`src-tauri/core/SHA256SUMS` pins the exact files the release embeds, and the build stops if
anything in that folder doesn't match. If you update a core, check it against the digests on its
release page and update `SHA256SUMS` too. Releases are always built with `npm run build:exe`;
a release build without the embedded cores is refused on purpose.

```bash
# Development (open the terminal as administrator if you want to try VPN mode)
npm run tauri dev

# The single-file release, written to src-tauri/target/release/phi2ray.exe
npm run build:exe
```

If you only want to work on the interface, `npm run dev` opens it in a browser with fake data.
Nothing touches your network that way.

<details>
<summary>Where things live</summary>

```
src/                    the interface (React)
src-tauri/src/
  connection.rs         connecting, disconnecting, and the watcher that keeps things alive
  firewall.rs           the kill switch
  config.rs, tun.rs     Xray and sing-box configs
  split.rs              split tunnel rules
  parser.rs             share links and subscriptions
  subscription.rs       downloading and merging subscriptions
  cores.rs              unpacking the bundled cores safely
  netinfo.rs            the connection info lookup
src-tauri/core/         Xray and sing-box binaries (not in git)
```
</details>

## Things people ask

**Google thinks I'm in Iran, but every other site shows the server's country.**
That's Google's own location database, not a leak. It figures out where an IP is from the phones
and Wi-Fi networks it sees behind it, and plenty of servers used from Iran end up tagged that way.
If [ipleak.net](https://ipleak.net) and [browserleaks.com/webrtc](https://browserleaks.com/webrtc)
don't show any Iranian IP or DNS server, you're fine.

**It says connected, but nothing loads.**
When traffic isn't getting through, the button turns orange and says "No internet". Set the log
level to *Info* in Settings, reconnect, and open Logs. The reason is usually sitting right there.

**Split tunnelling for apps doesn't do anything in System proxy mode.**
That's expected. Only VPN mode can see which app a connection comes from. Sites work in every mode.

**Some VLESS configs without TLS won't connect.**
Newer Xray versions refuse unencrypted VLESS unless the server is on a private network. That's
Xray protecting you, not something Phi2ray adds.

## Thanks

None of this would exist without [Xray-core](https://github.com/XTLS/Xray-core) (MPL-2.0),
[sing-box](https://github.com/SagerNet/sing-box) (GPL-3.0) and [Tauri](https://tauri.app).
Their licenses and links to their source code are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## License

Phi2ray's own code is under the [MIT License](LICENSE). The bundled cores keep their own licenses.

Use it responsibly, and within the laws that apply where you live.

If you run into a bug or have an idea, [open an issue](https://github.com/Phoenix15049/Phi2ray/issues).
I read them all.
