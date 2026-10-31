//! `phi2ray`: control the running Phi2ray app from a terminal.
//!
//! This program has no rights of its own: it runs as the user, unelevated, and only passes
//! commands to the app (which runs as administrator) over a local pipe. Turn it on in the app:
//! Settings → Console.

#[path = "../../src/ipc.rs"]
#[allow(dead_code)]
mod ipc;
mod pipe;
mod start;

use std::io::Read;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;
use serde_json::Value;

use ipc::{AddView, Command, DelayView, GroupView, LogsView, ServerView, StatusView, UpdateView};

const HELP: &str = "\
phi2ray - control Phi2ray from the command line

Usage: phi2ray <command> [options]

Connection
  status                    Show the connection (the default command)
  connect [SERVER]          Connect to SERVER, or to the selected server
  disconnect                Disconnect
  mode [vpn|proxy|manual]   Show or change the mode (reconnects if connected)
  killswitch [on|off]       Show or change the kill switch
  info                      Look up the exit and entry IPs (asks outside services)

Servers
  servers [GROUP]           List servers
  groups                    List groups and subscriptions
  test [SERVER...]          Measure delays (all servers, or --group GROUP)
  add LINK... | URL | -     Add links (- reads them from stdin) or a subscription URL
                            to the default group, or to --group GROUP
  update [GROUP]            Update subscriptions

App
  logs [-n N] [-f]          Show the last N log lines (30), -f to keep following
  show                      Open the window
  start                     Start Phi2ray in the tray
  quit                      Disconnect and close Phi2ray

SERVER and GROUP can be a number from the list, a name (or a unique part of one), or an id.
Add --json to any command for machine-readable output.

Console control must be on in Phi2ray: Settings → Console.";

/// What went wrong, and the exit code for it.
struct Failure {
    message: String,
    code: u8,
}

impl Failure {
    fn usage(message: impl Into<String>) -> Self {
        Self { message: format!("{}\nRun `phi2ray help` for the list of commands.", message.into()), code: 2 }
    }
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self { message, code: 1 }
    }
}

impl From<&str> for Failure {
    fn from(message: &str) -> Self {
        message.to_string().into()
    }
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let json = take_flag(&mut args, &["--json"]);
    match run(args, json) {
        Ok(()) => ExitCode::SUCCESS,
        Err(f) => {
            eprintln!("phi2ray: {}", f.message);
            ExitCode::from(f.code)
        }
    }
}

fn run(mut args: Vec<String>, json: bool) -> Result<(), Failure> {
    if args.is_empty() {
        args.push("status".into());
    }
    let command = args.remove(0);
    match command.as_str() {
        "help" | "-h" | "--help" | "/?" => {
            println!("{HELP}");
            Ok(())
        }
        "version" | "-V" | "--version" => {
            println!("phi2ray {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "status" | "st" => {
            no_more(&args)?;
            let s: StatusView = call(Command::Status)?;
            output(json, &s, print_status)
        }
        "connect" | "c" | "up" => {
            let server = joined(args);
            let s: StatusView = match call(Command::Connect { server: server.clone() }) {
                Err(f) if f.code == pipe::NOT_RUNNING => {
                    // Starting is what the user wants anyway: do it, then connect.
                    start::launch()?;
                    call(Command::Connect { server })?
                }
                other => other?,
            };
            output(json, &s, print_status)
        }
        "disconnect" | "d" | "dc" | "down" => {
            no_more(&args)?;
            let s: StatusView = call(Command::Disconnect)?;
            output(json, &s, print_status)
        }
        "mode" => {
            let mode = optional_one(args)?;
            let changing = mode.is_some();
            let data: Value = call(Command::Mode { mode })?;
            if json {
                return print_json(&data);
            }
            if changing {
                print_status(&serde_json::from_value(data).map_err(|e| e.to_string())?);
            } else {
                println!("{}", data.as_str().unwrap_or_default());
            }
            Ok(())
        }
        "killswitch" | "kill-switch" | "ks" => {
            let on = match optional_one(args)?.as_deref() {
                None => None,
                Some("on" | "true" | "1") => Some(true),
                Some("off" | "false" | "0") => Some(false),
                Some(other) => return Err(Failure::usage(format!("Use `on` or `off`, not \"{other}\"."))),
            };
            let data: Value = call(Command::KillSwitch { on })?;
            if json {
                return print_json(&data);
            }
            match on {
                Some(_) => print_status(&serde_json::from_value(data).map_err(|e| e.to_string())?),
                None => println!("{}", if data.as_bool() == Some(true) { "on" } else { "off" }),
            }
            Ok(())
        }
        "servers" | "ls" | "list" => {
            let group = joined(args);
            let servers: Vec<ServerView> = call(Command::Servers { group })?;
            output(json, &servers, print_servers)
        }
        "groups" | "subs" => {
            no_more(&args)?;
            let groups: Vec<GroupView> = call(Command::Groups)?;
            output(json, &groups, print_groups)
        }
        "test" | "ping" => {
            let group = take_option(&mut args, &["--group", "-g"])?;
            test(args, group, json)
        }
        "add" | "import" => {
            let group = take_option(&mut args, &["--group", "-g"])?;
            let text = if args.is_empty() || args == ["-"] {
                let mut text = String::new();
                std::io::stdin().read_to_string(&mut text).map_err(|e| format!("cannot read stdin: {e}"))?;
                text
            } else {
                args.join("\n")
            };
            let view: AddView = call(Command::Add { text, group })?;
            output(json, &view, |v| {
                match &v.group {
                    Some(g) => println!("Added subscription \"{g}\" with {} servers.", v.added),
                    None => println!("Added {} server{}.", v.added, plural(v.added)),
                }
                for e in &v.errors {
                    println!("  ! {e}");
                }
            })
        }
        "update" => {
            let group = joined(args);
            let mut views = Vec::new();
            let result: Result<Value, Failure> = call_with(Command::Update { group }, |data| {
                if let Ok(v) = serde_json::from_value::<UpdateView>(data.clone()) {
                    if !json {
                        match (&v.servers, &v.error) {
                            (Some(n), _) => println!("{}: {n} servers", v.group),
                            (_, Some(e)) => println!("{}: failed: {e}", v.group),
                            _ => {}
                        }
                    }
                }
                views.push(data);
            });
            if json {
                print_json(&Value::Array(views))?;
            }
            result.map(drop)
        }
        "logs" | "log" => logs(args, json),
        "info" | "ip" => {
            no_more(&args)?;
            let report: Value = call(Command::Info)?;
            output(json, &report, print_info)
        }
        "show" | "open" => {
            no_more(&args)?;
            call::<Value>(Command::Show).map(drop)
        }
        "start" => {
            no_more(&args)?;
            match call::<StatusView>(Command::Status) {
                Ok(s) => output(json, &s, print_status),
                Err(f) if f.code == pipe::NOT_RUNNING => {
                    start::launch()?;
                    let s: StatusView = call(Command::Status)?;
                    output(json, &s, print_status)
                }
                Err(f) => Err(f),
            }
        }
        "quit" | "exit" => {
            no_more(&args)?;
            call::<Value>(Command::Quit)?;
            if !json {
                println!("Phi2ray closed.");
            }
            Ok(())
        }
        other => Err(Failure::usage(format!("Unknown command \"{other}\"."))),
    }
}

// ---------- Talking to the app ----------

fn call<T: DeserializeOwned>(command: Command) -> Result<T, Failure> {
    let data = call_with(command, |_| {})?;
    serde_json::from_value(data).map_err(|e| format!("unexpected answer from Phi2ray: {e}").into())
}

fn call_with(command: Command, progress: impl FnMut(Value)) -> Result<Value, Failure> {
    pipe::request(&ipc::Request { version: ipc::VERSION, command }, progress)
}

// ---------- Commands with their own flow ----------

fn test(servers: Vec<String>, group: Option<String>, json: bool) -> Result<(), Failure> {
    let mut results: Vec<DelayView> = Vec::new();
    if !json {
        println!("Testing... (Ctrl+C to stop)");
    }
    let done = call_with(Command::Test { servers, group }, |data| {
        if let Ok(r) = serde_json::from_value::<DelayView>(data) {
            if !json {
                println!("{:>4}  {:<36} {}", r.number, fit(&r.name, 36), r.ms.map_or("timeout".into(), |ms| format!("{ms} ms")));
            }
            results.push(r);
        }
    })?;
    if json {
        return print_json(&serde_json::to_value(&results).map_err(|e| e.to_string())?);
    }
    let tested = done["tested"].as_u64().unwrap_or(results.len() as u64);
    let reachable = results.iter().filter(|r| r.ms.is_some()).count();
    print!("\n{reachable} of {tested} servers answered.");
    if let Some(best) = results.iter().filter(|r| r.ms.is_some()).min_by_key(|r| r.ms) {
        print!(" Fastest: {} {} ({} ms).", best.number, best.name, best.ms.unwrap_or(0));
    }
    println!();
    Ok(())
}

fn logs(mut args: Vec<String>, json: bool) -> Result<(), Failure> {
    let follow = take_flag(&mut args, &["-f", "--follow"]);
    let last = match take_option(&mut args, &["-n", "--lines"])? {
        Some(n) => n.parse::<usize>().map_err(|_| Failure::usage("-n needs a number."))?,
        None => 30,
    };
    no_more(&args)?;
    let mut since = None;
    let mut last = last;
    loop {
        let view: LogsView = call(Command::Logs { since, last })?;
        for line in &view.lines {
            if json {
                println!("{}", Value::String(line.clone()));
            } else {
                println!("{line}");
            }
        }
        if !follow {
            return Ok(());
        }
        since = Some(view.next);
        last = usize::MAX;
        std::thread::sleep(Duration::from_millis(700));
    }
}

// ---------- Output ----------

fn output<T: serde::Serialize>(json: bool, value: &T, human: impl FnOnce(&T)) -> Result<(), Failure> {
    if json {
        print_json(&serde_json::to_value(value).map_err(|e| e.to_string())?)
    } else {
        human(value);
        Ok(())
    }
}

fn print_json(value: &Value) -> Result<(), Failure> {
    println!("{}", serde_json::to_string_pretty(value).map_err(|e| e.to_string())?);
    Ok(())
}

fn print_status(s: &StatusView) {
    let mode = match s.mode.as_str() {
        "vpn" => "VPN mode",
        "proxy" => "System proxy mode",
        _ => "Manual mode",
    };
    let headline = match s.state.as_str() {
        "connected" => "Connected",
        "reconnecting" => "Reconnecting",
        _ if s.blocked => "Disconnected (internet blocked by the kill switch)",
        _ => "Disconnected",
    };
    println!("{headline} · {mode}");
    if let Some(server) = &s.server {
        let label = if s.state == "disconnected" { "Selected" } else { "Server" };
        row(label, &format!("{} {} ({}{})", server.number, server.name, server.protocol, transport(server)));
        if let Some(why) = &server.insecure {
            row("", &format!("! {}", insecure_text(why)));
        }
    }
    if s.state != "disconnected" {
        if let Some(ip) = &s.exit_ip {
            row("Exit IP", &format!("{ip}{}", s.exit_country.as_ref().map(|c| format!(" ({c})")).unwrap_or_default()));
        }
        match (s.healthy, s.latency_ms) {
            (Some(true), Some(ms)) => row("Latency", &format!("{ms} ms")),
            (Some(false), _) => row("Latency", "no answer"),
            _ => {}
        }
        row(
            "Traffic",
            &format!(
                "down {}/s  up {}/s  (total down {}, up {})",
                bytes(s.down_speed),
                bytes(s.up_speed),
                bytes(s.down_total),
                bytes(s.up_total)
            ),
        );
        if let Some(since) = s.connected_since {
            let reconnects = match s.reconnects {
                0 => String::new(),
                n => format!(", {n} reconnect{}", plural(n as usize)),
            };
            row("Connected", &format!("{}{reconnects}", duration_since(since)));
        }
        if let Some(port) = s.socks_port {
            let http = s.http_port.map(|p| format!(", HTTP 127.0.0.1:{p}")).unwrap_or_default();
            row("Local ports", &format!("SOCKS 127.0.0.1:{port}{http}"));
        }
    }
    row("Kill switch", if s.kill_switch { "on" } else { "off" });
}

fn print_servers(servers: &Vec<ServerView>) {
    if servers.is_empty() {
        println!("No servers. Add some with `phi2ray add <link>`.");
        return;
    }
    let mut group = None;
    for s in servers {
        if group != Some(&s.group) {
            println!("{}{}", if group.is_some() { "\n" } else { "" }, s.group);
            group = Some(&s.group);
        }
        let mark = if s.selected { "*" } else { " " };
        let warning = if s.insecure.is_some() { "  !" } else { "" };
        println!(
            "{mark}{:>4}  {:<32} {:<12} {}:{}{warning}",
            s.number,
            fit(&s.name, 32),
            format!("{}{}", s.protocol, transport(s)),
            s.address,
            s.port
        );
    }
    println!("\n* selected   ! not safely encrypted");
}

fn print_groups(groups: &Vec<GroupView>) {
    for g in groups {
        let mut detail = format!("{} server{}", g.servers, plural(g.servers));
        if g.subscription {
            detail.push_str(", subscription");
            if g.auto_update {
                detail.push_str(", updates automatically");
            }
            if let Some(at) = g.updated_at {
                detail.push_str(&format!(", updated {} ago", ago(at)));
            }
        }
        println!("{:>4}  {:<32} {detail}", g.number, fit(&g.name, 32));
        if let Some(e) = &g.last_error {
            println!("      ! last update failed: {e}");
        }
    }
}

fn print_info(report: &Value) {
    let geo_line = |g: &Value| -> String {
        if let Some(e) = g["error"].as_str() {
            return format!("unavailable ({e})");
        }
        let parts: Vec<String> = ["country", "region", "city", "asn", "org"]
            .iter()
            .filter_map(|k| g[*k].as_str().filter(|s| !s.is_empty()).map(String::from))
            .collect();
        let mut line = parts.join(" · ");
        if g["proxy"].as_bool() == Some(true) {
            line.push_str(" · flagged as proxy/VPN");
        }
        line
    };
    println!("Exit (what websites see)");
    if let Some(ip) = report["trace"]["ip"].as_str() {
        row("IP", ip);
    } else if let Some(ip) = report["exit"].as_array().and_then(|a| a.iter().find_map(|g| g["ip"].as_str())) {
        row("IP", ip);
    }
    for g in report["exit"].as_array().into_iter().flatten() {
        row(g["source"].as_str().unwrap_or("?"), &geo_line(g));
    }
    let entry = &report["entry"];
    if entry.is_object() {
        println!("\nEntry (your server)");
        let ip = entry["ip"].as_str().unwrap_or("?");
        let address = entry["address"].as_str().unwrap_or("?");
        row("Address", &if address == ip { ip.to_string() } else { format!("{address} -> {ip}") });
        if entry["public"].as_bool() == Some(false) {
            row("", "a private address: the server is reached through a local relay");
        }
        for g in entry["geo"].as_array().into_iter().flatten() {
            row(g["source"].as_str().unwrap_or("?"), &geo_line(g));
        }
    }
}

fn row(label: &str, value: &str) {
    println!("  {label:<12} {value}");
}

fn transport(s: &ServerView) -> String {
    if s.transport.is_empty() {
        String::new()
    } else {
        format!(", {}", s.transport)
    }
}

fn insecure_text(why: &str) -> &'static str {
    if why == "unencrypted" {
        "traffic to this server isn't encrypted"
    } else {
        "this server's certificate isn't checked"
    }
}

/// Cuts `text` to `width` characters, so columns stay lined up.
fn fit(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        text.to_string()
    } else {
        text.chars().take(width - 1).chain(Some('…')).collect()
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn duration_since(ms: u64) -> String {
    let secs = now_ms().saturating_sub(ms) / 1000;
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m {:02}s", s / 60, s % 60),
        s => format!("{}h {:02}m", s / 3600, s % 3600 / 60),
    }
}

fn ago(ms: u64) -> String {
    let mins = now_ms().saturating_sub(ms) / 60_000;
    match mins {
        m if m < 60 => format!("{m} min"),
        m if m < 48 * 60 => format!("{} h", m / 60),
        m => format!("{} days", m / 1440),
    }
}

// ---------- Arguments ----------

fn take_flag(args: &mut Vec<String>, names: &[&str]) -> bool {
    let before = args.len();
    args.retain(|a| !names.contains(&a.as_str()));
    args.len() != before
}

fn take_option(args: &mut Vec<String>, names: &[&str]) -> Result<Option<String>, Failure> {
    let Some(i) = args.iter().position(|a| names.contains(&a.as_str())) else { return Ok(None) };
    if i + 1 >= args.len() {
        return Err(Failure::usage(format!("{} needs a value.", args[i])));
    }
    let value = args.remove(i + 1);
    args.remove(i);
    Ok(Some(value))
}

fn no_more(args: &[String]) -> Result<(), Failure> {
    match args.first() {
        Some(extra) => Err(Failure::usage(format!("Unexpected \"{extra}\"."))),
        None => Ok(()),
    }
}

fn optional_one(args: Vec<String>) -> Result<Option<String>, Failure> {
    if args.len() > 1 {
        return Err(Failure::usage(format!("Unexpected \"{}\".", args[1])));
    }
    Ok(args.into_iter().next())
}

/// The rest of the words as one name, so `phi2ray connect Germany 1` needs no quotes.
fn joined(args: Vec<String>) -> Option<String> {
    (!args.is_empty()).then(|| args.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_are_taken_out_of_the_arguments() {
        let mut args: Vec<String> = ["a", "--group", "Work", "b"].map(String::from).to_vec();
        assert_eq!(take_option(&mut args, &["--group", "-g"]).ok().flatten().as_deref(), Some("Work"));
        assert_eq!(args, ["a", "b"]);
        let mut args: Vec<String> = vec!["-g".into()];
        assert!(take_option(&mut args, &["--group", "-g"]).is_err());
        assert_eq!(joined(vec!["Germany".into(), "1".into()]).as_deref(), Some("Germany 1"));
    }

    #[test]
    fn sizes_and_names_are_readable() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1536), "1.5 KB");
        assert_eq!(fit("abcdef", 4), "abc…");
        assert_eq!(fit("abc", 4), "abc");
    }
}
