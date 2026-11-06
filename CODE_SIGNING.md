# Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by
[SignPath Foundation](https://signpath.org)

> This applies once signing is approved and active. A release is signed if its exe shows
> SignPath Foundation as publisher; earlier releases aren't signed.

## What gets signed

Only `Phi2ray-<version>-windows-x64.exe`, built by the
[release workflow](.github/workflows/release.yml) on GitHub-hosted runners from the tagged
commit. Every release is approved by hand before it's signed.

The exe carries the unmodified upstream cores listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) (Xray-core and sing-box). They aren't signed by
this project. Each is pinned by hash in `src-tauri/core/SHA256SUMS`, and the build stops if one
doesn't match.

## Team

| Role | Members |
|---|---|
| Committers and reviewers | [@Phoenix15049](https://github.com/Phoenix15049) |
| Approvers | [@Phoenix15049](https://github.com/Phoenix15049) |

Changes proposed by anyone else are reviewed by a committer before they're merged. All team
members use multi-factor authentication on GitHub and SignPath.

## Privacy

See the [privacy policy](PRIVACY.md).

## System changes

Phi2ray changes the system only as you choose in the app, and each option says what it does:

- **VPN mode** adds a virtual network adapter and routes while connected.
- **System proxy mode** sets the Windows proxy while connected, then puts your settings back.
- **Kill switch** adds Windows firewall rules while connected.
- **Console control** (off by default) adds a folder to your own PATH.

## Removing Phi2ray

Phi2ray has no installer. To remove it:

1. Turn off *Settings → Console* if it's on, which takes the folder off your PATH.
2. Disconnect and quit Phi2ray. This removes its firewall rules and proxy settings.
3. Delete the exe.
4. Delete `C:\Program Files\Phi2ray`, which holds the unpacked cores and your saved servers.
5. Delete `%APPDATA%\com.phi2ray.app`, a small folder of Phi2ray's own.
