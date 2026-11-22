//! Import the single-peer client subset of wg-quick, TunSafe and Xray JSON.

use std::net::IpAddr;

use super::*;
use serde_json::json;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Client {
    secret_key: String,
    address: Vec<String>,
    peers: Vec<Peer>,
    #[serde(default)]
    no_kernel_tun: bool,
    #[serde(default = "default_mtu")]
    mtu: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reserved: Option<[u8; 3]>,
    #[serde(rename = "remoteDNS", default, skip_serializing_if = "Vec::is_empty")]
    remote_dns: Vec<IpAddr>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Peer {
    endpoint: String,
    public_key: String,
    #[serde(
        alias = "presharedKey",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pre_shared_key: Option<String>,
    #[serde(default)]
    keep_alive: u16,
    #[serde(rename = "allowedIPs", default = "default_routes")]
    allowed_ips: Vec<String>,
}

fn default_mtu() -> u16 {
    1420
}

fn default_routes() -> Vec<String> {
    vec!["0.0.0.0/0".into(), "::/0".into()]
}

fn clean(line: &str) -> &str {
    line.split('#').next().unwrap_or_default().trim()
}

pub(super) fn is_interface(line: &str) -> bool {
    clean(line).eq_ignore_ascii_case("[Interface]")
}

pub(super) fn contains_interface(text: &str) -> bool {
    text.trim_start_matches('\u{feff}')
        .lines()
        .any(is_interface)
}

pub(super) fn split_config(text: &str) -> (&str, &str) {
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let section = clean(line)
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
            .is_some_and(|name| {
                !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_alphabetic())
            });
        if offset != 0
            && (is_interface(line)
                || trimmed.starts_with('{')
                || (trimmed.starts_with('[') && !section)
                || scheme_of(trimmed) != "?")
        {
            break;
        }
        offset += line.len();
    }
    text.split_at(offset)
}

pub(super) fn parse_config(text: &str) -> Result<Profile, String> {
    if text.len() > 64 * 1024 {
        return Err("configuration is too large".into());
    }
    let mut fields = HashMap::<String, String>::new();
    let mut peer = false;
    for line in text
        .lines()
        .map(clean)
        .filter(|line| !line.is_empty())
        .skip(1)
    {
        if line.eq_ignore_ascii_case("[Peer]") {
            if peer {
                return Err("exactly one peer is supported".into());
            }
            peer = true;
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or("expected a field in [Interface] or [Peer]")?;
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        match (peer, key.as_str()) {
            (false, "address" | "dns") | (true, "allowedips") => {
                fields
                    .entry(key)
                    .and_modify(|current| {
                        current.push(',');
                        current.push_str(value);
                    })
                    .or_insert_with(|| value.into());
                continue;
            }
            (false, "privatekey" | "mtu")
            | (true, "publickey" | "presharedkey" | "endpoint" | "persistentkeepalive") => {}
            (false, "listenport") if value == "0" => continue,
            (false, "saveconfig" | "blockdns") if value.eq_ignore_ascii_case("false") => continue,
            (false, "preup" | "postup" | "predown" | "postdown") => {
                return Err("system hooks are not supported".into())
            }
            (false, "blockdns") => {
                return Err(
                    "TunSafe BlockDNS is unsupported; use Phi2ray's VPN protection settings".into(),
                )
            }
            _ => return Err("unsupported WireGuard/TunSafe option".into()),
        }
        if fields.insert(key, value.into()).is_some() {
            return Err("duplicate configuration field".into());
        }
    }
    if !peer {
        return Err("expected a [Peer] section".into());
    }
    let get = |key| fields.get(key).map(String::as_str).unwrap_or_default();
    let number = |key, default| {
        fields.get(key).map_or(Ok(default), |v| {
            v.parse::<u16>().map_err(|_| "invalid MTU or keepalive")
        })
    };
    let client = Client {
        secret_key: get("privatekey").into(),
        address: split_list(get("address")),
        peers: vec![Peer {
            endpoint: get("endpoint").into(),
            public_key: get("publickey").into(),
            pre_shared_key: fields.get("presharedkey").cloned(),
            keep_alive: number("persistentkeepalive", 0)?,
            allowed_ips: split_list(get("allowedips")),
        }],
        no_kernel_tun: true,
        mtu: number("mtu", default_mtu())?,
        reserved: None,
        remote_dns: split_list(get("dns"))
            .iter()
            .map(|dns| dns.parse::<IpAddr>())
            .collect::<Result<_, _>>()
            .map_err(|_| "DNS must contain IP addresses; search domains are unsupported")?,
    };
    make_profile(client, "")
}

pub(super) fn parse_json(outbound: &Value, name: &str) -> Result<Profile, String> {
    if ["streamSettings", "mux", "sendThrough", "targetStrategy"]
        .iter()
        .any(|key| !outbound[key].is_null())
    {
        return Err("WireGuard requires a standalone UDP outbound".into());
    }
    let settings = outbound
        .get("settings")
        .ok_or("missing WireGuard settings")?;
    let client =
        Client::deserialize(settings).map_err(|_| "invalid or unsupported WireGuard settings")?;
    make_profile(client, name)
}

fn make_profile(mut client: Client, name: &str) -> Result<Profile, String> {
    if client.peers.len() != 1 {
        return Err("exactly one peer is supported".into());
    }
    if client.address.is_empty() || client.address.len() > 32 || client.remote_dns.len() > 32 {
        return Err("expected 1–32 interface addresses and at most 32 DNS servers".into());
    }
    for address in &mut client.address {
        let (ip, prefix) = cidr(address, false).ok_or("invalid interface address")?;
        if !usable_ip(ip) {
            return Err("invalid interface address".into());
        }
        *address = format!("{ip}/{prefix}");
    }
    if client.remote_dns.iter().any(|ip| !usable_ip(*ip)) {
        return Err("invalid DNS server address".into());
    }
    let min_mtu = if client.address.iter().any(|address| address.contains(':')) {
        1280
    } else {
        576
    };
    if !(min_mtu..=9000).contains(&client.mtu) {
        return Err("MTU is out of range for the interface addresses".into());
    }
    client.secret_key = key(&client.secret_key, "invalid or missing private key")?;
    client.no_kernel_tun = true;

    let peer = &mut client.peers[0];
    let (address, port) = endpoint(&peer.endpoint)?;
    peer.endpoint = format_endpoint(&address, port);
    peer.public_key = key(&peer.public_key, "invalid or missing peer public key")?;
    if let Some(psk) = &mut peer.pre_shared_key {
        *psk = key(psk, "invalid preshared key")?;
    }
    if peer.allowed_ips.is_empty() || peer.allowed_ips.len() > 512 {
        return Err("expected 1–512 AllowedIPs routes".into());
    }
    for subnet in &mut peer.allowed_ips {
        let (ip, prefix) = cidr(subnet, true).ok_or("invalid AllowedIPs subnet")?;
        *subnet = format!("{ip}/{prefix}");
    }

    Ok(Profile {
        id: new_id(),
        name: or(name, &format_endpoint(&address, port)),
        protocol: Protocol::Wireguard,
        address,
        port,
        secret: String::new(),
        method: String::new(),
        flow: String::new(),
        alter_id: 0,
        group_id: String::new(),
        stream: Stream {
            network: "udp".into(),
            security: "none".into(),
            ..Default::default()
        },
        outbound_settings: Some(
            serde_json::to_value(client).map_err(|_| "invalid WireGuard configuration")?,
        ),
        mux: None,
        library: LibraryPreferences::default(),
    })
}

fn key(input: &str, error: &'static str) -> Result<String, String> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let bytes = if input.len() == 64 {
        hex::decode(input).map_err(|_| error)?
    } else {
        STANDARD
            .decode(input)
            .or_else(|_| STANDARD_NO_PAD.decode(input))
            .or_else(|_| URL_SAFE.decode(input))
            .or_else(|_| URL_SAFE_NO_PAD.decode(input))
            .map_err(|_| error)?
    };
    if bytes.len() != 32 || bytes.iter().all(|&byte| byte == 0) {
        return Err(error.into());
    }
    Ok(STANDARD.encode(bytes))
}

fn usable_ip(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_loopback()
        && !matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
        && !matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some())
}

fn endpoint(input: &str) -> Result<(String, u16), String> {
    if input.contains("://") {
        return Err("only standard UDP endpoints are supported".into());
    }
    let (host, port) = input
        .rsplit_once(':')
        .ok_or("missing endpoint host or port")?;
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or("invalid endpoint port")?;
    if let Some(ip) = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        let ip = ip
            .parse::<std::net::Ipv6Addr>()
            .ok()
            .filter(|ip| usable_ip((*ip).into()) && !ip.is_unicast_link_local())
            .ok_or("invalid IPv6 endpoint")?;
        return Ok((ip.to_string(), port));
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        if !usable_ip(ip.into()) || ip.is_link_local() {
            return Err("invalid IPv4 endpoint".into());
        }
        return Ok((ip.to_string(), port));
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.len() > 253
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        || host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    {
        return Err("invalid endpoint hostname; IPv6 endpoints need brackets".into());
    }
    Ok((host.to_ascii_lowercase(), port))
}

fn format_endpoint(address: &str, port: u16) -> String {
    if address.contains(':') {
        format!("[{address}]:{port}")
    } else {
        format!("{address}:{port}")
    }
}

fn cidr(value: &str, network: bool) -> Option<(IpAddr, u8)> {
    let (address, prefix) = value
        .split_once('/')
        .map_or((value, None), |(addr, bits)| (addr, Some(bits)));
    let ip: IpAddr = address.parse().ok()?;
    let width = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(bits) => bits.parse::<u8>().ok()?,
        None if network => return None,
        None => width,
    };
    if prefix > width {
        return None;
    }
    let ip = if !network {
        ip
    } else {
        match ip {
            IpAddr::V4(ip) => std::net::Ipv4Addr::from(
                u32::from(ip) & u32::MAX.checked_shl(u32::from(width - prefix)).unwrap_or(0),
            )
            .into(),
            IpAddr::V6(ip) => std::net::Ipv6Addr::from(
                u128::from(ip)
                    & u128::MAX
                        .checked_shl(u32::from(width - prefix))
                        .unwrap_or(0),
            )
            .into(),
        }
    };
    Some((ip, prefix))
}

pub(crate) fn permits_ipv4(p: &Profile) -> bool {
    let Some(settings) = &p.outbound_settings else {
        return false;
    };
    settings["address"]
        .as_array()
        .is_some_and(|a| a.iter().any(is_ipv4_text))
        && settings["peers"][0]["allowedIPs"]
            .as_array()
            .is_some_and(|a| a.iter().any(is_ipv4_text))
}

pub(crate) fn full_ipv4(p: &Profile) -> bool {
    let Some(settings) = &p.outbound_settings else {
        return false;
    };
    let Some(routes) = settings["peers"][0]["allowedIPs"].as_array() else {
        return false;
    };
    permits_ipv4(p)
        && (routes.contains(&json!("0.0.0.0/0"))
            || (routes.contains(&json!("0.0.0.0/1")) && routes.contains(&json!("128.0.0.0/1"))))
}

pub(crate) fn outbound(p: &Profile, ipv4_only: bool) -> Value {
    let mut settings = p.outbound_settings.clone().unwrap_or_else(|| json!({}));
    if let Some(peer) = settings.get_mut("peers").and_then(|peers| peers.get_mut(0)) {
        peer["endpoint"] = json!(format_endpoint(&p.address, p.port));
    }
    if ipv4_only {
        if let Some(addresses) = settings["address"].as_array_mut() {
            addresses.retain(is_ipv4_text);
        }
        if let Some(routes) = settings["peers"][0]["allowedIPs"].as_array_mut() {
            routes.retain(is_ipv4_text);
        }
        if let Some(servers) = settings.get_mut("remoteDNS").and_then(Value::as_array_mut) {
            servers.retain(is_ipv4_text);
        }
    }
    settings["noKernelTun"] = json!(true);
    json!({ "tag": "proxy", "protocol": "wireguard", "settings": settings })
}

fn is_ipv4_text(value: &Value) -> bool {
    value.as_str().is_some_and(|address| !address.contains(':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> String {
        let b64 = base64::engine::general_purpose::STANDARD;
        format!(
            concat!(
                "# example client\r\n[Interface]\r\nPrivateKey = {}\r\n",
                "Address = 10.7.0.2/24\r\nAddress = fd00::2/128 # comment\r\n",
                "DNS = 10.7.0.1, fd00::1\r\nMTU = 1380\r\n",
                "[Peer]\r\nPublicKey = {}\r\nPresharedKey = {}\r\n",
                "Endpoint = vpn.example.invalid:51820\r\nAllowedIPs = 0.0.0.0/0\r\n",
                "AllowedIPs = ::/0\r\nPersistentKeepalive = 25\r\n",
            ),
            b64.encode([1; 32]),
            b64.encode([2; 32]),
            b64.encode([3; 32])
        )
    }

    #[test]
    fn imports_mixed_wireguard_tunsafe_and_standard_exports() {
        let conf = fixture();
        let saved = parse_many(&conf).profiles.remove(0);
        let archive = crate::config::for_export(&saved);
        let mixed = format!(
            "\u{feff}{conf}\n{}\n# standard share link from another client\ntrojan://test@relay.invalid:443#Standard\n{}",
            json!([archive]), conf.replace("vpn.example.invalid:51820", "[2001:db8::7]:51820"),
        );
        for body in [
            mixed.clone(),
            base64::engine::general_purpose::STANDARD.encode(mixed),
        ] {
            let parsed = parse_many(&body);
            assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
            assert_eq!(parsed.profiles.len(), 4);
            assert_eq!(parsed.profiles[0].protocol, Protocol::Wireguard);
            assert_eq!(crate::config::for_export(&parsed.profiles[1]), archive);
            assert_eq!(parsed.profiles[2].protocol, Protocol::Trojan);
            assert_eq!(parsed.profiles[3].address, "2001:db8::7");
        }
    }

    #[test]
    fn builds_userspace_config_with_matching_pin_and_private_view() {
        let profile = parse_many(&fixture()).profiles.remove(0);
        let export = crate::config::for_export(&profile);
        let settings = &export["outbounds"][0]["settings"];
        assert_eq!(settings["mtu"], 1380);
        assert_eq!(settings["remoteDNS"], json!(["10.7.0.1", "fd00::1"]));
        assert_eq!(settings["peers"][0]["keepAlive"], 25);
        let mut incoming = export;
        incoming["outbounds"][0]["settings"]["noKernelTun"] = json!(false);
        let profile = parse_many(&incoming.to_string()).profiles.remove(0);
        let pin = crate::connection::pin_address(&profile, "2001:db8::9".parse().unwrap());
        let config = outbound(&pin, true);
        assert_eq!(config["settings"]["noKernelTun"], true);
        assert_eq!(
            config["settings"]["peers"][0]["endpoint"],
            "[2001:db8::9]:51820"
        );
        assert_eq!(config["settings"]["address"], json!(["10.7.0.2/24"]));
        assert_eq!(
            config["settings"]["peers"][0]["allowedIPs"],
            json!(["0.0.0.0/0"])
        );
        assert_eq!(config["settings"]["remoteDNS"], json!(["10.7.0.1"]));
        assert!(crate::absolute::validate_profile(&profile).is_ok());
        assert!(crate::absolute::validate_profile(
            &parse_many(&fixture().replace("0.0.0.0/0", "10.7.0.0/24"),)
                .profiles
                .remove(0)
        )
        .is_err());
        let view = serde_json::to_value(profile.view()).unwrap();
        assert_eq!(view["protocol"], "wireguard");
        assert!(view["insecure"].is_null());
        assert!(view.get("secret").is_none() && view.get("outboundSettings").is_none());
    }

    #[test]
    fn rejects_unsafe_or_unusable_settings_without_echoing_input() {
        let conf = fixture();
        for unsafe_config in [
            conf.replace("MTU = 1380", "PostUp = SENSITIVE_COMMAND"),
            conf.replace("MTU = 1380", "BlockDNS = true"),
            conf.replace("MTU = 1380", "MTU = 65000"),
            conf.replace("[Peer]", "[Peer]\n[Peer]"),
            conf.replace("51820", "0"),
            conf.replace(
                "vpn.example.invalid:51820",
                "tcp://vpn.example.invalid:51820",
            ),
            conf.replace("10.7.0.1", "secret.domain.invalid"),
            conf.replace("::/0", "::/130"),
            conf.replace(
                &base64::engine::general_purpose::STANDARD.encode([1; 32]),
                "SENSITIVE_KEY",
            ),
        ] {
            let parsed = parse_many(&unsafe_config);
            assert!(parsed.profiles.is_empty());
            assert_eq!(parsed.errors.len(), 1);
            assert!(!parsed.errors[0].contains("SENSITIVE"));
            assert!(!parsed.errors[0].contains("secret.domain.invalid"));
        }
        let mut json_export = crate::config::for_export(&parse_many(&conf).profiles.remove(0));
        json_export["outbounds"][0]["streamSettings"] =
            json!({"sockopt":{"interface":"would-bypass"}});
        assert!(parse_many(&json_export.to_string()).profiles.is_empty());
        let protected = parse_many("npv://SENSITIVE");
        assert!(protected.profiles.is_empty());
        assert!(!protected.errors[0].contains("SENSITIVE"));
    }
}
