# How Phi2ray works

The [README](../README.md) covers using Phi2ray. This page is for people who want to know what it
does under the hood and why.

```
 your apps ──► Phi2ray VPN adapter (sing-box) ──► Xray ──► your server ──► internet
                          │                         │
                          └──── DNS over HTTPS ─────┘
```

- **sing-box** only handles the virtual network adapter, routing and DNS. It hands every
  connection to Xray, so any transport Xray supports also works in VPN mode.
- **Xray** talks to your server. Its own connection is routed around the tunnel by the system
  itself, so it can't loop back into it.
- Your server details reach the cores through stdin and are never written to disk as plain text.

## Windows and Linux

The two versions share everything above, the interface and the connection logic. They differ in
how they get the rights a VPN needs.

| | Windows | Linux |
|---|---|---|
| Who runs as admin | The whole app (one UAC prompt at start) | Only `phi2ray-helper`, started through `pkexec` the first time it's needed |
| Cores live in | `C:\Program Files\Phi2ray`, unpacked from the exe | `/usr/lib/phi2ray`, from the package (`/opt/phi2ray` for the AppImage) |
| Cores run as | Elevated | The `phi2ray-core` system account, not root |
| Kill switch | Windows Filtering Platform | An nftables table |
| Saved servers | DPAPI | A key in the desktop's keyring |
| System proxy | WinINet | GNOME (GSettings) and KDE (`kioslaverc`) settings |
| Console pipe | Named pipe | Unix socket in `$XDG_RUNTIME_DIR/phi2ray` |

### The Linux helper

On Linux the window never runs as root. A web view has no business being root, and Wayland
wouldn't show it anyway. Everything that needs root is in one small program with three
dependencies, `src-tauri/helper`.

- `pkexec` starts it with pipes on its stdin and stdout. There's no socket and no background
  service, so only the app that started it can talk to it. It's gone when the app is, and nothing
  runs as root while the app isn't running.
- It runs cores only from its own folder, and refuses to start if anyone but root could change
  that folder.
- Xray runs as `phi2ray-core` with no extra rights. sing-box runs as the same account, with only
  the five capabilities its own systemd unit asks for. Both lose every other capability, can't gain
  new ones, and die with the helper.
- It doesn't take the app's word for the sing-box config: it accepts exactly the shape Phi2ray
  builds and refuses anything that could name a file or open a control port
  (`check_tun_config` in `src-tauri/src/helper_protocol.rs`).
- The proxy modes without the kill switch need no root at all, so no password is asked for.

## The kill switch

It's a set of firewall rules, not a timer. While it's on, only these get out:

- loopback,
- the two cores. On Windows only as Phi2ray starts them, with administrator rights. On Linux only
  the `phi2ray-core` account, which only root can use,
- traffic through the VPN adapter,
- DHCP and IPv6 link-local, so your network keeps working,
- your local network, if you want printers and the router to stay reachable.

It fails closed. If Phi2ray crashes, the rules stay and the app offers to reconnect or unblock
when opened again. The rules are never saved, so restarting always clears them and you can't be
locked out for good. The flip side is that they aren't active until Phi2ray starts.

Replacing the rules never leaves a gap: Windows adds the new set before removing the old one, and
Linux swaps them in a single nftables transaction. On Linux the rules also cover forwarded
traffic, so containers and virtual machines can't go around them.

## Keeping things private

- Local proxy ports are random each time and only reachable from this computer. SOCKS always asks
  for a username and password, and VPN mode has no HTTP port at all. The proxy modes do have an HTTP
  port without a password, because system proxy settings can't hold one.
- Before Xray counts as started, Phi2ray checks that its ports really belong to it, so another
  program can't grab one first and pose as the proxy.
- In System proxy mode, automatic proxy detection (WPAD) and setup scripts are off while you're
  connected, so a fake one on public Wi-Fi can't send your browser around the proxy.
- Your server's name is looked up over encrypted DNS before connecting, so your network's DNS
  doesn't see it. Fake private answers for a filtered server (like `10.10.34.36`) are ignored. The
  last good address is remembered for 30 days, so reconnecting works when DNS can't be reached.
- Saved servers are encrypted for your account, which keeps them safe if the file is copied
  somewhere else. Programs running as you can still read them, as with any app. On Linux systems
  with no keyring the key sits in a file next to them, readable only by you, which protects less.
- Subscriptions are capped at 8 MB and 2000 servers. A redirect from `https` to `http` is refused,
  as is one to this computer or the local network. Plain `http://` subscriptions never update by
  themselves.
- Error messages never include a subscription link or a server's password, so logs are safe to
  share, and the window itself never receives your servers' passwords.

## Staying connected

- Phi2ray only reports *connected* once the VPN adapter is really up.
- When something breaks, only the broken piece restarts and the tunnel stays up, so your apps wait
  instead of falling back to your real connection.
- If the server stops answering, Xray is restarted after 15 seconds, then less and less often (up
  to every two minutes), since every restart drops all open connections.
- While connected, subscription updates and the DNS test always go through your server, even when
  the split tunnel would send other traffic directly.

## Protecting the cores on Windows

Phi2ray runs as admin there, so anyone able to swap a core would gain admin rights. The cores are
unpacked into `C:\Program Files\Phi2ray`, where only administrators can change anything. Each file
is checked against the hash recorded at build time and kept open with writing blocked until
Phi2ray exits. Your data lives in the same place, in a folder per account, so Phi2ray never writes
where other programs could redirect it.

## Console control

It's off until you turn it on. The `phi2ray` command talks to the app over a local channel only
your account can open, and never from another computer. Commands do what the window does, and no
answer includes a server password or the SOCKS credentials. While it's on, programs running as you
can control the connection and read the log, so leave it off if you don't use it.

On Windows the command also checks that the other end belongs to Administrators, which only
Phi2ray itself can do. On Linux the app runs as you, so that check doesn't exist: the command
trusts your own runtime folder, and the app checks that the caller is your account.

## What doesn't go through the tunnel

- Your local network, while *Local network outside the VPN* is on.
- Apps and sites you exclude with split tunnel, or with *Only via VPN*, everything you didn't list.
- Iranian sites, if you turn that option on. Their names are also looked up with your network's
  DNS.
- Anything addressed to your server's own IP. That's how the tunnel itself gets out; it only matters
  if your server sits behind a CDN address other sites share.
- *Test* on the server list connects straight to each server, as every client does.

## Where things live

```
src/                      the interface (React)
src-tauri/src/
  connection.rs           connecting, disconnecting, and the watcher that keeps things alive
  firewall.rs             the kill switch
  config.rs, tun.rs       Xray and sing-box configs
  split.rs                split tunnel rules
  parser.rs               share links and subscriptions
  subscription.rs         downloading and merging subscriptions
  netinfo.rs              the connection info lookup
  platform.rs             what differs between systems (Linux: the *_linux.rs files)
  helper.rs               the app's end of the Linux helper
  helper_protocol.rs      what both ends agree on, including the nftables rules
src-tauri/helper/         the Linux helper
src-tauri/cli/            the phi2ray command
src-tauri/core/           Xray and sing-box binaries (not in git)
packaging/arch/           the Arch package
```
