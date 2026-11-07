# Privacy policy

Phi2ray has no accounts, telemetry, analytics or update check, and there's no Phi2ray server.
Your servers, subscriptions and settings stay on your computer, encrypted for your account.
Logs are kept in memory only and are gone when Phi2ray closes.

Phi2ray only contacts other systems for the things below.

## Systems you choose

- **Your servers and subscription links**, when you connect, test or update them. *Test* contacts
  each server directly, so it sees your real IP, as with any client.
- **Your DNS server** (Settings → DNS), for lookups in VPN mode. It's reached through your
  connection. The default is Cloudflare.
- **Your test URL** (Settings → Diagnostics), to check that traffic gets through. It's requested
  through your server after connecting, every 15 seconds while connected, and during *Test*.
  The default is Google's `generate_204`.

## Systems Phi2ray chooses

- **Encrypted DNS: Cloudflare (`1.1.1.1`), Google (`8.8.8.8`) and Quad9 (`9.9.9.9`).** When you
  connect in VPN mode or with the kill switch on, and your server is a domain name, they're asked
  for that name, so your network's DNS doesn't see it. If they don't answer and no address was
  confirmed in the last 7 days, your system's DNS is asked instead. Using a server's IP address
  in its link avoids these lookups entirely.
- **Cloudflare (`1.1.1.1/cdn-cgi/trace`).** Asked through your connection after connecting, to
  show your exit IP and country.
- **Connection info: ipapi.co, DB-IP, FreeIPAPI, Cloudflare and proxycheck.io.** Only when you
  open that page. They receive your exit IP and your server's IP, and every request goes through
  your server. For the IP quality check, your exit IP is also looked up on public DNS blocklists
  (Barracuda, blocklist.de, DroneBL, SpamCop and s5h) through Cloudflare's encrypted DNS.

The map on that page places you from your computer's time zone. That stays on your computer.

These services have their own privacy policies. Your server's operator can see the traffic you
send through it, as with any VPN or proxy.
