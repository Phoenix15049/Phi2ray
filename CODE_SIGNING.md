# Code signing policy

Windows releases can use [SignPath.io](https://about.signpath.io) with a trusted code-signing
certificate. Eligible projects can apply for a certificate from [SignPath Foundation](https://signpath.org/apply).
The publisher Windows verifies is the certificate's subject. **Properties → Details** shows
the developer name stored in the file metadata. **Properties → Digital Signatures** shows
who signed the file.

For releases signed with the Foundation's certificate:

> Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org)

## Configure signing on GitHub

1. Set up a SignPath project and signing policy with a trusted code-signing certificate.
   Use the repository's [artifact configuration](.signpath/artifact-configuration.xml) and
   follow the [GitHub integration guide](https://docs.signpath.io/trusted-build-systems/github).
2. In the GitHub repository, open **Settings → Secrets and variables → Actions**. Create
   `SIGNPATH_ORGANIZATION_ID`, `SIGNPATH_PROJECT_SLUG` and `SIGNPATH_POLICY_SLUG` under
   **Variables**. Add `SIGNPATH_API_TOKEN` under **Secrets**, using a SignPath identity allowed
   to submit signing requests for that policy.
3. Run the Release workflow from `main` and check the **Windows signing** summary. This
   checks that the settings are present and produces an unsigned test artifact. A tagged
   run submits the actual signing request. Approve it in SignPath if the policy requires
   approval. SignPath Foundation requires approval for every release. The workflow verifies
   the Authenticode signature and timestamp before drafting the release.

For an intentionally unsigned release, remove incomplete SignPath settings and set the
repository Actions variable `ALLOW_UNSIGNED_WINDOWS_RELEASE` to `true`. The release notes
identify the unsigned executable. Microsoft Defender SmartScreen may still warn on first
download even for a correctly signed release. [Microsoft's signing and reputation guidance](https://learn.microsoft.com/windows/apps/package-and-deploy/smartscreen-reputation)

## What gets signed

Only `Phi2ray-<version>-windows-x64.exe`, built by the
[release workflow](.github/workflows/release.yml) on GitHub-hosted runners from the tagged
commit. The signing policy determines approval. Linux packages come from the same workflow
with SHA-256 checksums and a build attestation in the release.

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
- **System proxy mode** sets the system's proxy while connected, then puts your settings back.
- **Kill switch** adds firewall rules while connected.
- **Console control** (off by default) adds a folder to your own PATH on Windows.

## Removing Phi2ray

**On Linux**, remove the package (`sudo apt remove phi2ray`, `sudo dnf remove phi2ray` or
`sudo pacman -R phi2ray-bin`), or delete the AppImage file. Your saved servers
are in `~/.local/share/com.phi2ray.app`. The package leaves the small `phi2ray-core` system account
behind; `sudo userdel phi2ray-core` removes it.

**On Windows** Phi2ray has no installer. To remove it:

1. Turn off *Settings → Console* if it's on, which takes the folder off your PATH.
2. Disconnect and quit Phi2ray. This removes its firewall rules and proxy settings.
3. Delete the exe.
4. Delete `C:\Program Files\Phi2ray`, which holds the unpacked cores and your saved servers.
5. Delete `%APPDATA%\com.phi2ray.app`, a small folder of Phi2ray's own.
