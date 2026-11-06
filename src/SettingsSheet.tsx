import { ReactNode, useEffect, useRef, useState } from "react";
import { About, api, Mode, Settings, Status } from "./api";
import { StringKey, T, useT } from "./i18n";
import { Icon, revealInStrip, Segmented, Sheet, Switch } from "./ui";

export const modeOptions = (t: T): { id: Mode; label: string; hint: string }[] => [
  { id: "tun", label: t("modeVpn"), hint: t("modeVpnHint") },
  { id: "system", label: t("modeSystem"), hint: t("modeSystemHint") },
  { id: "manual", label: t("modeManual"), hint: t("modeManualHint") },
];

const DNS_PRESETS: { value: string; label: string; tag?: StringKey }[] = [
  { value: "https://1.1.1.1/dns-query", label: "Cloudflare", tag: "dnsTagFast" },
  { value: "https://8.8.8.8/dns-query", label: "Google" },
  { value: "https://9.9.9.9/dns-query", label: "Quad9", tag: "dnsTagMalware" },
  { value: "https://dns.adguard-dns.com/dns-query", label: "AdGuard", tag: "dnsTagAds" },
  { value: "https://dns.mullvad.net/dns-query", label: "Mullvad", tag: "dnsTagNoLogs" },
  { value: "https://doh.dns.sb/dns-query", label: "DNS.SB", tag: "dnsTagNoLogs" },
  { value: "https://doh.opendns.com/dns-query", label: "OpenDNS" },
];

const TEST_URL_PRESETS = [
  { value: "http://www.gstatic.com/generate_204", label: "Google" },
  { value: "http://cp.cloudflare.com/generate_204", label: "Cloudflare" },
];

const CUSTOM = "custom";

const LOG_LINES = [100, 500, 1000, 2000, 5000];

type Props = {
  settings: Settings;
  status: Status;
  about: About | null;
  busy: boolean;
  needsReconnect: boolean;
  covered: boolean;
  onChange: (patch: Partial<Settings>) => void;
  onModeChange: (mode: Mode) => void;
  onReconnect: () => void;
  onOpenSplit: () => void;
  onClose: () => void;
};

const SECTIONS: { key: StringKey; icon: () => ReactNode }[] = [
  { key: "appearance", icon: Icon.palette },
  { key: "connection", icon: Icon.plug },
  { key: "protection", icon: Icon.shield },
  { key: "splitTunnel", icon: () => Icon.split() },
  { key: "routing", icon: Icon.route },
  { key: "dns", icon: Icon.globe },
  { key: "vpnAdapter", icon: Icon.chip },
  { key: "localProxy", icon: Icon.hash },
  { key: "diagnostics", icon: Icon.pulse },
  { key: "consoleSection", icon: Icon.terminal },
  { key: "about", icon: Icon.info },
];

/** One icon per section; the current one opens up to show its name. Follows the scroll, and jumps on a click. */
function SectionNav() {
  const t = useT();
  const [current, setCurrent] = useState<StringKey>(SECTIONS[0].key);
  const strip = useRef<HTMLElement>(null);
  const jumped = useRef(0);

  useEffect(() => {
    const body = strip.current?.parentElement?.querySelector<HTMLElement>(".page-body");
    if (!body) return;
    const onScroll = () => {
      if (Date.now() - jumped.current < 600) return;
      const line = body.getBoundingClientRect().top + 72;
      let found = SECTIONS[0].key;
      for (const { key } of SECTIONS) {
        const section = body.querySelector(`[data-section="${key}"]`);
        if (section && section.getBoundingClientRect().top <= line) found = key;
      }
      if (body.scrollTop + body.clientHeight >= body.scrollHeight - 2) found = SECTIONS[SECTIONS.length - 1].key;
      setCurrent(found);
    };
    body.addEventListener("scroll", onScroll, { passive: true });
    return () => body.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    revealInStrip(strip.current, strip.current?.querySelector(".active"));
  }, [current]);

  const jump = (key: StringKey) => {
    jumped.current = Date.now();
    setCurrent(key);
    const body = strip.current?.parentElement?.querySelector(".page-body");
    body?.querySelector(`[data-section="${key}"]`)?.scrollIntoView({ block: "start", behavior: "smooth" });
  };

  return (
    <nav className="section-nav" ref={strip} aria-label={t("settings")}>
      {SECTIONS.map(({ key, icon }) => (
        <button key={key} className={key === current ? "active" : ""} onClick={() => jump(key)} aria-label={t(key)} title={t(key)}>
          {icon()}
          <span className="section-name">
            <span>{t(key)}</span>
          </span>
        </button>
      ))}
    </nav>
  );
}

export function SettingsSheet(p: Props) {
  const t = useT();
  const s = p.settings;
  return (
    <Sheet title={t("settings")} onClose={p.onClose} covered={p.covered} subhead={<SectionNav />}>
      {p.needsReconnect && (
        <div className="reconnect-bar">
          <span>{t("reconnectToApply")}</span>
          <button className="btn small primary" onClick={p.onReconnect} disabled={p.busy}>
            {t("reconnect")}
          </button>
        </div>
      )}

      <Section id="appearance">
        <Group>
          <Row icon={Icon.language()} title={t("language")}>
            <Segmented
              label={t("language")}
              value={s.language}
              options={[
                { value: "en", label: "English" },
                { value: "fa", label: "فارسی" },
              ]}
              onChange={(language) => p.onChange({ language })}
            />
          </Row>
          <Row icon={Icon.moon()} title={t("theme")}>
            <Segmented
              label={t("theme")}
              value={s.theme}
              options={[
                { value: "system", label: t("themeSystem") },
                { value: "light", label: t("themeLight") },
                { value: "dark", label: t("themeDark") },
              ]}
              onChange={(theme) => p.onChange({ theme })}
            />
          </Row>
          <Row icon={Icon.pin()} title={t("alwaysOnTop")} hint={t("alwaysOnTopHint")}>
            <Switch checked={s.alwaysOnTop} onChange={(v) => p.onChange({ alwaysOnTop: v })} label={t("alwaysOnTop")} />
          </Row>
          <Row icon={Icon.tray()} title={t("minimizeToTray")} hint={t("minimizeToTrayHint")}>
            <Switch checked={s.minimizeToTray} onChange={(v) => p.onChange({ minimizeToTray: v })} label={t("minimizeToTray")} />
          </Row>
        </Group>
      </Section>

      <Section id="connection">
        <div className="choices">
          {modeOptions(t).map((m) => (
            <button
              key={m.id}
              className={`choice ${s.mode === m.id ? "active" : ""}`}
              onClick={() => p.onModeChange(m.id)}
              disabled={p.busy}
            >
              <span className="choice-icon">{m.id === "tun" ? Icon.shield() : m.id === "system" ? Icon.globe() : Icon.plug()}</span>
              <span className="choice-text">
                <strong>
                  {m.label}
                  {m.id === "tun" && <em>{t("defaultBadge")}</em>}
                </strong>
                <span>{m.hint}</span>
              </span>
              {s.mode === m.id && <span className="choice-check">{Icon.check()}</span>}
            </button>
          ))}
        </div>
        <Group>
          <Row icon={Icon.play()} title={t("connectOnLaunch")} hint={t("connectOnLaunchHint")}>
            <Switch checked={s.autoConnect} onChange={(v) => p.onChange({ autoConnect: v })} label={t("connectOnLaunch")} />
          </Row>
        </Group>
      </Section>

      <Section id="protection">
        <Group>
          <Row icon={Icon.lock(18)} title={t("killSwitch")} hint={t("killSwitchHint")}>
            <Switch checked={s.killSwitch} onChange={(v) => p.onChange({ killSwitch: v })} label={t("killSwitch")} />
          </Row>
          <Row icon={Icon.refresh()} title={t("autoReconnect")} hint={t("autoReconnectHint")}>
            <Switch checked={s.autoReconnect} onChange={(v) => p.onChange({ autoReconnect: v })} label={t("autoReconnect")} />
          </Row>
        </Group>
      </Section>

      <Section id="splitTunnel">
        <button className="nav-row" onClick={p.onOpenSplit}>
          <span className="choice-icon">{Icon.split()}</span>
          <span className="row-text">
            <strong>{t("splitTunnel")}</strong>
            <span>
              {!s.split.enabled
                ? t("splitOff")
                : `${s.split.mode === "exclude" ? t("splitExclude") : t("splitInclude")} · ${s.split.apps.length} ${t("splitAppsCount")} · ${s.split.sites.length} ${t("splitSitesCount")}`}
            </span>
          </span>
          <span className="nav-chevron">{Icon.chevron()}</span>
        </button>
      </Section>

      <Section id="routing">
        <Group>
          <Row icon={Icon.home()} title={t("bypassLan")} hint={t("bypassLanHint")}>
            <Switch checked={s.bypassLan} onChange={(v) => p.onChange({ bypassLan: v })} label={t("bypassLan")} />
          </Row>
          <Row icon={Icon.flag()} title={t("iranDirect")} hint={t("iranDirectHint")}>
            <Switch checked={s.iranDirect} onChange={(v) => p.onChange({ iranDirect: v })} label={t("iranDirect")} />
          </Row>
          <Row icon={Icon.ban()} title={t("blockAds")} hint={t("blockAdsHint")}>
            <Switch checked={s.blockAds} onChange={(v) => p.onChange({ blockAds: v })} label={t("blockAds")} />
          </Row>
          <Row icon={Icon.noBolt()} title={t("blockQuic")} hint={t("blockQuicHint")}>
            <Switch checked={s.blockQuic} onChange={(v) => p.onChange({ blockQuic: v })} label={t("blockQuic")} />
          </Row>
        </Group>
      </Section>

      <Section id="dns" hint={t("dnsHint")}>
        <DnsPicker value={s.remoteDns} connected={!!p.status.session} onCommit={(remoteDns) => p.onChange({ remoteDns })} />
        <Group>
          <Row icon={Icon.globe()} title={t("ipv6")} hint={t("ipv6Hint")}>
            <Switch checked={s.ipv6} onChange={(v) => p.onChange({ ipv6: v })} label={t("ipv6")} />
          </Row>
        </Group>
      </Section>

      <Section id="vpnAdapter">
        <Group>
          <Row icon={Icon.layers()} title={t("networkStack")} hint={t("networkStackHint")}>
            <select className="select" value={s.tunStack} onChange={(e) => p.onChange({ tunStack: e.target.value as Settings["tunStack"] })}>
              <option value="mixed">Mixed</option>
              <option value="system">System</option>
              <option value="gvisor">gVisor</option>
            </select>
          </Row>
          <Row icon={Icon.ruler()} title={t("mtu")} hint={t("mtuHint")}>
            <NumberField label={t("mtu")} value={s.tunMtu} min={1280} max={9000} onCommit={(v) => p.onChange({ tunMtu: v })} />
          </Row>
          <Row icon={Icon.route()} title={t("strictRoute")} hint={t("strictRouteHint")}>
            <Switch checked={s.strictRoute} onChange={(v) => p.onChange({ strictRoute: v })} label={t("strictRoute")} />
          </Row>
        </Group>
      </Section>

      <Section id="localProxy" hint={t("localProxyHint")}>
        <Group>
          <Row icon={Icon.pin()} title={t("fixedPorts")} hint={t("fixedPortsHint")}>
            <Switch checked={s.fixedPorts} onChange={(v) => p.onChange({ fixedPorts: v })} label={t("fixedPorts")} />
          </Row>
          {s.fixedPorts && (
            <>
              <Row icon={Icon.hash()} title={t("socksPort")}>
                <NumberField label={t("socksPort")} value={s.socksPort} min={1024} max={65535} onCommit={(v) => p.onChange({ socksPort: v })} />
              </Row>
              <Row icon={Icon.hash()} title={t("httpPort")}>
                <NumberField label={t("httpPort")} value={s.httpPort} min={1024} max={65535} onCommit={(v) => p.onChange({ httpPort: v })} />
              </Row>
            </>
          )}
        </Group>
      </Section>

      <Section id="diagnostics">
        <Group>
          <Row icon={Icon.pulse()} title={t("logLevel")} hint={t("logLevelHint")}>
            <select className="select" value={s.logLevel} onChange={(e) => p.onChange({ logLevel: e.target.value as Settings["logLevel"] })}>
              <option value="warning">Warning</option>
              <option value="info">Info</option>
              <option value="debug">Debug</option>
            </select>
          </Row>
          <Row icon={Icon.list()} title={t("logLines")} hint={t("logLinesHint")}>
            <select className="select" value={s.logLines} onChange={(e) => p.onChange({ logLines: Number(e.target.value) })}>
              {LOG_LINES.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </Row>
          <Row icon={Icon.link()} title={t("testUrl")} hint={t("testUrlHint")}>
            <PresetOrCustom value={s.testUrl} presets={TEST_URL_PRESETS} placeholder="http://…" onCommit={(v) => p.onChange({ testUrl: v })} />
          </Row>
        </Group>
      </Section>

      <Section id="consoleSection">
        <Group>
          <Row icon={Icon.terminal()} title={t("consoleCommand")} hint={t("consoleCommandHint")}>
            <Switch checked={s.console} onChange={(v) => p.onChange({ console: v })} label={t("consoleCommand")} />
          </Row>
        </Group>
        {s.console && (
          <p className="hint selectable">
            {t("consoleOnHint")} <code className="ltr">phi2ray help</code>
          </p>
        )}
      </Section>

      <Section id="about">
        <dl className="facts">
          <dt>Phi2ray</dt>
          <dd className="ltr">{p.about?.app ?? "…"}</dd>
          <dt>{t("xrayCore")}</dt>
          <Fact found={p.status.xrayFound} version={p.about?.xray} />
          <dt>{t("singBox")}</dt>
          <Fact found={p.status.tunFound} version={p.about?.singBox} />
          <dt>{t("administrator")}</dt>
          <dd className={p.status.elevated ? "ok" : ""}>{p.status.elevated ? t("yes") : t("no")}</dd>
        </dl>
        {p.about && (
          <p className="hint selectable">
            {t("coresFolder")}: <span className="ltr">{p.about.coreDir}</span>
            <br />
            {t("dataFolder")}: <span className="ltr">{p.about.dataDir}</span>
          </p>
        )}
      </Section>

      <p className="credit">
        {t("madeBy")}{" "}
        <button className="link ltr" onClick={() => api.openLink("github").catch(() => {})}>
          @Phoenix15049
        </button>
        <span aria-hidden="true"> · </span>
        <button className="link ltr" onClick={() => api.openLink("site").catch(() => {})}>
          inosila.com
        </button>
      </p>
    </Sheet>
  );
}

/** DNS server list with a real lookup test, so the fastest working server is easy to pick. */
function DnsPicker(props: { value: string; connected: boolean; onCommit: (v: string) => void }) {
  const t = useT();
  const isPreset = DNS_PRESETS.some((d) => d.value === props.value);
  const [custom, setCustom] = useState(isPreset ? "" : props.value);
  const [results, setResults] = useState<Record<string, number | null | "testing">>({});
  const [testedConnected, setTestedConnected] = useState<boolean | null>(null);
  const [testing, setTesting] = useState(false);

  useEffect(() => {
    if (!DNS_PRESETS.some((d) => d.value === props.value)) setCustom(props.value);
  }, [props.value]);

  const servers = [...DNS_PRESETS.map((d) => d.value), ...(custom.trim() ? [custom.trim()] : [])];

  const runTest = async () => {
    setTesting(true);
    setResults(Object.fromEntries(servers.map((s) => [s, "testing" as const])));
    try {
      const ms = await api.pingDns(servers);
      setResults(Object.fromEntries(servers.map((s, i) => [s, ms[i] ?? null])));
      setTestedConnected(props.connected);
    } finally {
      setTesting(false);
    }
  };

  const result = (server: string) => {
    if (!server.startsWith("https://")) return <span className="latency">{t("dnsNotTestable")}</span>;
    const r = results[server];
    if (r === undefined) return null;
    if (r === "testing") return <span className="latency testing">···</span>;
    if (r === null) return <span className="latency bad">{t("failed")}</span>;
    return <span className={`latency ${r < 150 ? "good" : r < 400 ? "mid" : "slow"}`}><span className="ltr">{r} ms</span></span>;
  };

  return (
    <div className="dns-picker">
      <div className="group">
        {DNS_PRESETS.map((d) => (
          <label key={d.value} className={`dns-row ${props.value === d.value ? "active" : ""}`}>
            <input type="radio" name="dns" checked={props.value === d.value} onChange={() => props.onCommit(d.value)} />
            <span className="dns-name">
              <strong>
                {d.label}
                {d.tag && <em className="dns-tag">{t(d.tag)}</em>}
              </strong>
              <span className="ltr">{d.value.replace("https://", "")}</span>
            </span>
            {result(d.value)}
          </label>
        ))}
        <label className={`dns-row ${!isPreset ? "active" : ""}`}>
          <input
            type="radio"
            name="dns"
            checked={!isPreset}
            onChange={() => custom.trim() && props.onCommit(custom.trim())}
            disabled={!custom.trim()}
          />
          <span className="dns-name grow">
            <strong>{t("dnsCustom")}</strong>
            <TextField value={custom} placeholder={t("dnsCustomPlaceholder")} onCommit={(v) => { setCustom(v); props.onCommit(v); }} />
          </span>
          {custom.trim() && result(custom.trim())}
        </label>
      </div>
      <div className="dns-foot">
        <span className="hint">{testedConnected === null ? "" : testedConnected ? t("dnsTestedThrough") : t("dnsTestedDirect")}</span>
        <button className="btn small" onClick={runTest} disabled={testing}>
          {Icon.bolt()}
          {t("dnsTest")}
        </button>
      </div>
    </div>
  );
}

function Section(props: { id: StringKey; hint?: string; children: ReactNode }) {
  const t = useT();
  const icon = SECTIONS.find((s) => s.key === props.id)?.icon;
  return (
    <section className="settings-section" data-section={props.id}>
      <h3>
        <span className="section-icon">{icon?.()}</span>
        {t(props.id)}
      </h3>
      {props.hint && <p className="section-hint">{props.hint}</p>}
      {props.children}
    </section>
  );
}

function Group({ children }: { children: ReactNode }) {
  return <div className="group">{children}</div>;
}

function Row(props: { icon?: ReactNode; title: string; hint?: string; children: ReactNode }) {
  return (
    <div className="row-setting">
      {props.icon && <span className="row-icon">{props.icon}</span>}
      <div className="row-text">
        <strong>{props.title}</strong>
        {props.hint && <span>{props.hint}</span>}
      </div>
      <div className="row-control">{props.children}</div>
    </div>
  );
}

function Fact({ found, version }: { found: boolean; version?: string | null }) {
  const t = useT();
  if (!found) return <dd className="missing">{t("missing")}</dd>;
  return <dd className="ok ltr">{version ?? t("found")}</dd>;
}

/** Text input that only reports its value on Enter or when it loses focus. */
function TextField(props: { value: string; placeholder?: string; onCommit: (v: string) => void }) {
  const [draft, setDraft] = useState(props.value);
  useEffect(() => setDraft(props.value), [props.value]);
  const commit = () => {
    const v = draft.trim();
    if (v && v !== props.value) props.onCommit(v);
    else setDraft(props.value);
  };
  return (
    <input
      className="input ltr-input"
      value={draft}
      placeholder={props.placeholder}
      spellCheck={false}
      onChange={(e) => setDraft(e.target.value)}
      onBlur={commit}
      onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLInputElement).blur()}
    />
  );
}

function NumberField(props: { label: string; value: number; min: number; max: number; onCommit: (v: number) => void }) {
  const [draft, setDraft] = useState(String(props.value));
  useEffect(() => setDraft(String(props.value)), [props.value]);
  const commit = () => {
    const v = Number(draft);
    if (Number.isInteger(v) && v !== props.value) props.onCommit(v);
    else setDraft(String(props.value));
  };
  return (
    <input
      className="input number ltr-input"
      inputMode="numeric"
      value={draft}
      onChange={(e) => setDraft(e.target.value.replace(/\D/g, ""))}
      onBlur={commit}
      onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLInputElement).blur()}
      aria-label={props.label}
      title={`${props.min}–${props.max}`}
    />
  );
}

function PresetOrCustom(props: {
  value: string;
  presets: { value: string; label: string }[];
  placeholder: string;
  onCommit: (v: string) => void;
}) {
  const t = useT();
  const isPreset = props.presets.some((x) => x.value === props.value);
  const [custom, setCustom] = useState(!isPreset);
  useEffect(() => {
    if (!props.presets.some((x) => x.value === props.value)) setCustom(true);
  }, [props.value, props.presets]);

  return (
    <div className="preset-field">
      <select
        className="select"
        value={custom ? CUSTOM : props.value}
        onChange={(e) => {
          if (e.target.value === CUSTOM) return setCustom(true);
          setCustom(false);
          props.onCommit(e.target.value);
        }}
      >
        {props.presets.map((x) => (
          <option key={x.value} value={x.value}>
            {x.label}
          </option>
        ))}
        <option value={CUSTOM}>{t("dnsCustom")}…</option>
      </select>
      {custom && <TextField value={props.value} placeholder={props.placeholder} onCommit={props.onCommit} />}
    </div>
  );
}
