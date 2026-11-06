import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { About, ADMIN_REQUIRED, api, DEFAULT_GROUP, DelayResult, Group, Mode, onEvent, Profile, Settings, Status } from "./api";
import logo from "./assets/logo.svg";
import { DEFAULT_SETTINGS } from "./defaults";
import { AddKind, AddSheet, GroupSheet, looksLikeSubscription } from "./GroupSheets";
import { I18n, makeT, StringKey } from "./i18n";
import { InfoSheet } from "./InfoSheet";
import { Iris, Rays, RayState } from "./Rays";
import { modeOptions, SettingsSheet } from "./SettingsSheet";
import { SplitSheet } from "./SplitSheet";
import {
  countryName,
  Delay,
  formatBytes,
  formatDuration,
  formatSpeed,
  Icon,
  Latency,
  Presence,
  ProtocolBadge,
  revealInStrip,
  Segmented,
  Sheet,
  Spark,
  timeAgo,
  useSlidingMarker,
} from "./ui";

type Phase = "idle" | "connecting" | "connected" | "reconnecting" | "disconnecting";
type SheetName = "add" | "settings" | "split" | "info" | "logs" | "admin" | "group" | "quit" | null;
type Toast = { id: number; kind: "info" | "error"; text: string };

const PHASE_LABEL: Record<Phase, StringKey> = {
  idle: "notConnected",
  connecting: "connecting",
  connected: "connected",
  reconnecting: "reconnecting",
  disconnecting: "disconnecting",
};

/** Settings that take effect without reconnecting. */
const LIVE_SETTINGS: (keyof Settings)[] = [
  "selected",
  "autoConnect",
  "testUrl",
  "version",
  "killSwitch",
  "autoReconnect",
  "language",
  "theme",
  "alwaysOnTop",
  "minimizeToTray",
];

/** `inert` takes hidden parts of the stage and deck out of the tab order. */
const inert = (on: boolean) => (on ? ({ inert: "" } as object) : {});

/** The part of the app a log line came from, for its colour. */
const logTag = (line: string) => (line.startsWith("[app]") ? "app" : line.startsWith("[console]") ? "app" : line.startsWith("[tun]") ? "tun" : line.startsWith("[xray]") ? "xray" : "");

const EMPTY_STATUS: Status = {
  session: null,
  firewall: false,
  blocked: false,
  xrayFound: true,
  tunFound: true,
  elevated: true,
  coreError: null,
};

export default function App() {
  const [groups, setGroups] = useState<Group[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const [status, setStatus] = useState<Status>(EMPTY_STATUS);
  const [pending, setPending] = useState<"connecting" | "disconnecting" | null>(null);
  const [needsReconnect, setNeedsReconnect] = useState(false);
  const [activeGroup, setActiveGroup] = useState(DEFAULT_GROUP);
  const [updating, setUpdating] = useState<string | null>(null);
  const [delays, setDelays] = useState<Record<string, Delay>>({});
  const [testing, setTesting] = useState(false);
  const [query, setQuery] = useState("");
  const [sortByDelay, setSortByDelay] = useState(false);
  const [sheet, setSheet] = useState<SheetName>(null);
  const [deckOpen, setDeckOpen] = useState(false);
  const [addPreset, setAddPreset] = useState<{ kind: AddKind; text: string }>({ kind: "links", text: "" });
  const [logs, setLogs] = useState<string[]>([]);
  const [about, setAbout] = useState<About | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [now, setNow] = useState(Date.now());
  const pendingRef = useRef(pending);
  pendingRef.current = pending;
  const hadSession = useRef(false);
  const logBox = useRef<HTMLDivElement>(null);
  const logFollow = useRef(true);
  const deckScroll = useRef<HTMLDivElement>(null);
  const lastDeckScroll = useRef(0);

  const t = useMemo(() => makeT(settings.language), [settings.language]);
  const tRef = useRef(t);
  tRef.current = t;

  const session = status.session;
  const phase: Phase = pending ?? (session ? session.state : "idle");
  const busy = pending !== null;
  const live = phase === "connected" || phase === "reconnecting";

  // Language direction and theme live on <html>, so sheets and toasts follow too.
  useEffect(() => {
    const root = document.documentElement;
    root.lang = settings.language;
    root.dir = settings.language === "fa" ? "rtl" : "ltr";
    root.dataset.theme = settings.theme;
  }, [settings.language, settings.theme]);

  const toast = useCallback((kind: Toast["kind"], text: string) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t.slice(-2), { id, kind, text }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), kind === "error" ? 7000 : 3500);
  }, []);

  const reload = useCallback(async () => {
    const s = await api.getState();
    setGroups(s.groups);
    setProfiles(s.profiles);
    setSettings(s.settings);
    return s;
  }, []);

  const refreshStatus = useCallback(async () => {
    const st = await api.status();
    setStatus(st);
    if (hadSession.current && !st.session && !pendingRef.current) {
      toast("error", tRef.current(st.blocked ? "connectionLostBlocked" : "connectionLost"));
    }
    hadSession.current = !!st.session;
    return st;
  }, [toast]);

  const handleConnectError = useCallback(
    (e: unknown) => {
      const msg = String(e);
      if (msg.includes(ADMIN_REQUIRED)) setSheet("admin");
      else toast("error", msg);
    },
    [toast],
  );

  const connect = useCallback(
    async (id: string) => {
      setPending("connecting");
      try {
        const s = await api.connect(id);
        hadSession.current = true;
        setStatus((st) => ({ ...st, session: s, blocked: false }));
        setSettings((st) => ({ ...st, selected: id }));
        setNeedsReconnect(false);
      } catch (e) {
        handleConnectError(e);
      } finally {
        setPending(null);
        refreshStatus().catch(() => {});
      }
    },
    [handleConnectError, refreshStatus],
  );

  const disconnect = async () => {
    setPending("disconnecting");
    try {
      await api.disconnect();
    } catch (e) {
      toast("error", String(e));
    } finally {
      hadSession.current = false;
      setNeedsReconnect(false);
      setPending(null);
      refreshStatus().catch(() => {});
    }
  };

  useEffect(() => {
    let first = true;
    (async () => {
      try {
        const [state, st] = await Promise.all([reload(), refreshStatus()]);
        const selected = state.profiles.find((p) => p.id === state.settings.selected);
        if (selected) setActiveGroup(selected.groupId);
        if (first && state.settings.autoConnect && selected && !st.session) connect(selected.id);
      } catch (e) {
        toast("error", String(e));
      }
      first = false;
    })();

    const offs = [
      onEvent<DelayResult>("delay", (r) => setDelays((d) => ({ ...d, [r.id]: r.ms }))),
      onEvent("groups-changed", () => reload().catch(() => {})),
      onEvent("state-changed", () => {
        hadSession.current = false;
        refreshStatus().catch(() => {});
      }),
      onEvent<string>("connect-error", handleConnectError),
      onEvent("close-requested", () => setSheet("quit")),
    ];
    return () => offs.forEach((off) => off.then((f) => f()));
  }, [reload, refreshStatus, connect, toast, handleConnectError]);

  // Faster polling while connected keeps the speed display smooth.
  useEffect(() => {
    const timer = setInterval(() => refreshStatus().catch(() => {}), live ? 1000 : 2000);
    return () => clearInterval(timer);
  }, [live, refreshStatus]);

  useEffect(() => {
    if (!live) return;
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [live]);

  // Logs are fetched only while visible, so a busy core never slows the window.
  useEffect(() => {
    if (sheet !== "logs") return;
    const load = () => api.getLogs().then(setLogs).catch(() => {});
    load();
    const timer = setInterval(load, 1000);
    return () => clearInterval(timer);
  }, [sheet]);

  // Follows new lines, unless the user scrolled up to read.
  useEffect(() => {
    const box = logBox.current;
    if (sheet === "logs" && box && logFollow.current) box.scrollTop = box.scrollHeight;
  }, [logs, sheet]);

  useEffect(() => {
    if (sheet === "settings") api.about().then(setAbout).catch(() => {});
  }, [sheet]);

  // Fall back to the default tab if the active group disappears.
  useEffect(() => {
    if (groups.length && !groups.some((g) => g.id === activeGroup)) setActiveGroup(DEFAULT_GROUP);
  }, [groups, activeGroup]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const p of profiles) c[p.groupId] = (c[p.groupId] ?? 0) + 1;
    return c;
  }, [profiles]);

  const { strip, marker } = useSlidingMarker(activeGroup, [groups, counts, settings.language]);

  // Keep the active tab in view.
  useEffect(() => {
    revealInStrip(strip.current, strip.current?.querySelector(".tab.active"));
  }, [activeGroup, groups.length, strip]);

  // Escape folds the deck away (a page or dialog on top takes it first).
  useEffect(() => {
    if (!deckOpen || sheet) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setDeckOpen(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [deckOpen, sheet]);

  const saveSettings = async (next: Settings) => {
    const previous = settings;
    setSettings(next);
    try {
      setSettings(await api.updateSettings(next));
      return true;
    } catch (e) {
      setSettings(previous);
      handleConnectError(e);
      return false;
    }
  };

  const togglePower = () => {
    if (busy) return;
    if (live) return disconnect();
    if (!settings.selected) return toast("info", t("addServerFirst"));
    return connect(settings.selected);
  };

  const select = async (id: string) => {
    if (busy) return;
    const saved = await saveSettings({ ...settings, selected: id });
    if (saved && live && session?.profileId !== id) connect(id);
  };

  const changeMode = async (mode: Mode) => {
    if (busy || mode === settings.mode) return;
    const saved = await saveSettings({ ...settings, mode });
    if (saved && live && settings.selected) connect(settings.selected);
  };

  const changeSettings = async (patch: Partial<Settings>) => {
    const saved = await saveSettings({ ...settings, ...patch });
    const needsRestart = (Object.keys(patch) as (keyof Settings)[]).some((k) => !LIVE_SETTINGS.includes(k));
    if (saved && live && needsRestart) setNeedsReconnect(true);
    if (saved && "killSwitch" in patch) refreshStatus().catch(() => {});
  };

  const openAdd = async () => {
    let preset: { kind: AddKind; text: string } = { kind: "links", text: "" };
    try {
      const clip = (await navigator.clipboard.readText()).trim();
      if (looksLikeSubscription(clip)) preset = { kind: "subscription", text: clip };
      else if (clip.includes("://") || /^[A-Za-z0-9+/=_-]{40,}$/.test(clip)) preset = { kind: "links", text: clip };
    } catch {
      // Clipboard access can be denied; the user can paste manually.
    }
    setAddPreset(preset);
    setSheet("add");
  };

  const addLinks = async (text: string, groupId: string) => {
    try {
      const r = await api.importLinks(text, groupId);
      await reload();
      setActiveGroup(groupId);
      if (r.added) toast("info", `${t("added")}: ${r.added}`);
      if (r.errors.length) toast("error", `${t("skipped")}: ${r.errors.length}\n${r.errors.slice(0, 3).join("\n")}`);
      return r.added > 0;
    } catch (e) {
      toast("error", String(e));
      return false;
    }
  };

  const addSubscription = async (url: string) => {
    try {
      const r = await api.addSubscription(url);
      await reload();
      setActiveGroup(r.groupId);
      toast("info", `${t("added")}: ${r.count}${r.skipped ? ` · ${r.skipped} ${t("unsupportedSkipped")}` : ""}`);
      if (url.trim().toLowerCase().startsWith("http:")) toast("error", t("httpSubscriptionAdded"));
      return true;
    } catch (e) {
      toast("error", String(e));
      return false;
    }
  };

  const createGroup = async (name: string) => {
    try {
      const id = await api.createGroup(name);
      await reload();
      setActiveGroup(id);
      return true;
    } catch (e) {
      toast("error", String(e));
      return false;
    }
  };

  const updateSubscription = async (id: string) => {
    if (updating) return;
    setUpdating(id);
    try {
      const r = await api.updateSubscription(id);
      toast("info", `${t("updatedServers")}: ${r.count}`);
    } catch (e) {
      toast("error", String(e));
    } finally {
      await reload().catch(() => {});
      setUpdating(null);
    }
  };

  const saveGroup = async (name: string, url?: string, autoUpdate?: boolean) => {
    try {
      await api.updateGroup(activeGroup, name, url, autoUpdate);
      await reload();
      return true;
    } catch (e) {
      toast("error", String(e));
      return false;
    }
  };

  const deleteGroup = async () => {
    try {
      const inUse = profiles.some((p) => p.groupId === activeGroup && p.id === session?.profileId);
      if (inUse) await disconnect();
      await api.deleteGroup(activeGroup);
      setActiveGroup(DEFAULT_GROUP);
      await reload();
      return true;
    } catch (e) {
      toast("error", String(e));
      return false;
    }
  };

  const remove = async (id: string) => {
    if (session?.profileId === id) await disconnect();
    try {
      await api.deleteProfile(id);
      await reload();
    } catch (e) {
      toast("error", String(e));
    }
  };

  const groupProfiles = useMemo(() => profiles.filter((p) => p.groupId === activeGroup), [profiles, activeGroup]);

  const testGroup = async () => {
    if (testing || !groupProfiles.length) return;
    const ids = groupProfiles.map((p) => p.id);
    setTesting(true);
    setDelays((d) => ({ ...d, ...Object.fromEntries(ids.map((id) => [id, "testing" as Delay])) }));
    try {
      await api.testDelays(ids);
    } catch (e) {
      toast("error", String(e));
    } finally {
      setDelays((d) => Object.fromEntries(Object.entries(d).map(([k, v]) => [k, v === "testing" ? null : v])));
      setTesting(false);
    }
  };

  const checkHealth = async () => {
    try {
      await api.checkConnection();
      await refreshStatus();
    } catch (e) {
      toast("error", String(e));
    }
  };

  const copy = (text: string) => {
    navigator.clipboard.writeText(text).then(
      () => toast("info", t("copied")),
      () => toast("error", t("clipboardFailed")),
    );
  };

  /** Vertical wheel scrolls the tab strip sideways. */
  const onTabsWheel = (e: React.WheelEvent<HTMLDivElement>) => {
    if (Math.abs(e.deltaY) > Math.abs(e.deltaX)) e.currentTarget.scrollLeft += settings.language === "fa" ? -e.deltaY : e.deltaY;
  };

  /** Scrolling down over the stage brings the servers up, unless the stage itself has to scroll. */
  const onStageWheel = (e: React.WheelEvent<HTMLElement>) => {
    const el = e.currentTarget;
    if (e.deltaY > 0 && el.scrollHeight <= el.clientHeight + 1) setDeckOpen(true);
  };

  /** Scrolling further up at the top of the list folds it away; a scroll that just got there doesn't. */
  const onDeckWheel = (e: React.WheelEvent<HTMLDivElement>) => {
    const atTop = (deckScroll.current?.scrollTop ?? 0) <= 0;
    if (e.deltaY < 0 && atTop && Date.now() - lastDeckScroll.current > 250) setDeckOpen(false);
  };

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = q
      ? groupProfiles.filter((p) => `${p.name} ${p.address} ${p.protocol} ${p.stream.network}`.toLowerCase().includes(q))
      : groupProfiles;
    if (!sortByDelay) return list;
    const rank = (d: Delay) => (typeof d === "number" ? d : d === "testing" ? 1e6 : 1e7);
    return [...list].sort((a, b) => rank(delays[a.id]) - rank(delays[b.id]));
  }, [groupProfiles, query, sortByDelay, delays]);

  const selected = profiles.find((p) => p.id === settings.selected);
  const group = groups.find((g) => g.id === activeGroup);
  const sub = group?.subscription;
  const health = session?.health;
  const traffic = session?.traffic;
  const unhealthy = phase === "connected" && health && !health.ok;
  const rayState: RayState = status.blocked && !session ? "blocked" : unhealthy || phase === "reconnecting" ? "warning" : phase;
  // Apps can only be split in VPN mode; sites in every mode.
  const split = settings.split;
  const splitActive = split.enabled && (split.sites.length > 0 || (settings.mode === "tun" && split.apps.length > 0));
  const modes = modeOptions(t);

  // The built-in group keeps its translated name until the user renames it.
  const groupName = (g: Group) => (g.id === DEFAULT_GROUP && g.name === "My servers" ? t("myServers") : g.name);

  const selectedGroup = groups.find((g) => g.id === selected?.groupId);

  const expiryText = (expireSeconds: number) => {
    const days = Math.ceil((expireSeconds * 1000 - Date.now()) / 86_400_000);
    if (days < 0) return t("expired");
    if (days === 0) return t("expiresToday");
    return `${days} ${t("daysLeft")}`;
  };

  const word = status.blocked && !session ? t("blockedTitle") : unhealthy ? t("noInternet") : t(PHASE_LABEL[phase]);
  const serverName = selected ? selected.name : t("noServerSelected");
  const powerLabel = live ? t("disconnect") : t("connect");

  return (
    <I18n.Provider value={t}>
      <div className={`shell ${deckOpen ? "deck-open" : ""}`} data-phase={rayState}>
        <header className="titlebar" data-tauri-drag-region>
          <span className="mark" data-tauri-drag-region>
            <img src={logo} alt="" aria-hidden="true" data-tauri-drag-region />
            Phi2ray
          </span>
          <div className="title-tools">
            <button className="icon-btn" onClick={() => setSheet("info")} aria-label={t("connectionInfo")} title={t("connectionInfo")}>
              {Icon.info()}
            </button>
            <button className="icon-btn" onClick={() => setSheet("logs")} aria-label={t("logs")} title={t("logs")}>
              {Icon.terminal()}
            </button>
            <button className="icon-btn" onClick={() => setSheet("settings")} aria-label={t("settings")} title={t("settings")}>
              {Icon.settings()}
            </button>
            <span className="title-gap" aria-hidden="true" />
            <button className="window-btn" onClick={() => api.minimizeWindow().catch(() => {})} aria-label={t("minimize")} title={t("minimize")}>
              {Icon.minimize()}
            </button>
            <button className="window-btn close" onClick={() => api.closeWindow().catch(() => {})} aria-label={t("close")} title={t("close")}>
              {Icon.windowClose()}
            </button>
          </div>
        </header>

        <main className="stage" onWheel={onStageWheel} {...inert(deckOpen)}>
          {status.coreError ? (
            <div className="alert warn">
              {t("coreUnpackFailed")}
              <span className="alert-detail ltr">{status.coreError}</span>
            </div>
          ) : (
            !status.xrayFound && <div className="alert warn">{t("xrayMissing")}</div>
          )}

          <div className="status">
            <h1 className="word" key={word}>
              {word}
            </h1>
            <div className="status-row">
              <span className="status-server">{serverName}</span>
              {live && (status.firewall || splitActive) && (
                <span className="seals">
                  {status.firewall && (
                    <span title={t("killSwitchOn")} aria-label={t("killSwitchOn")}>
                      {Icon.lock()}
                    </span>
                  )}
                  {splitActive && (
                    <span
                      title={`${t("splitActive")} · ${t(split.mode === "exclude" ? "splitExclude" : "splitInclude")}`}
                      aria-label={t("splitActive")}
                    >
                      {Icon.split(12)}
                    </span>
                  )}
                </span>
              )}
              {live && session && <span className="clock ltr">{formatDuration(now - session.startedAt)}</span>}
            </div>
          </div>

          <div className="field">
            <Rays
              state={rayState}
              down={traffic?.downSpeed ?? 0}
              up={traffic?.upSpeed ?? 0}
              mirror={settings.language === "fa"}
              paused={deckOpen || sheet === "settings" || sheet === "split" || sheet === "info" || sheet === "logs"}
            />
            <span className="field-end near">{t("thisPc")}</span>
            {live && session?.exit && (
              <button className="field-end far" onClick={() => setSheet("info")} title={t("whatSitesSee")}>
                <strong>{session.exit.country ? countryName(session.exit.country, settings.language) : t("infoInternet")}</strong>
                <span className="ltr">{session.exit.ip}</span>
              </button>
            )}
            <button className="lens" onClick={togglePower} disabled={busy} aria-label={powerLabel} title={powerLabel}>
              <Iris />
            </button>
          </div>

          {status.blocked && !session && (
            <div className="alert danger">
              <span>{t("blockedBanner")}</span>
              <div className="alert-actions">
                <button className="btn small primary" onClick={() => settings.selected && connect(settings.selected)} disabled={busy}>
                  {t("reconnect")}
                </button>
                <button className="btn small" onClick={disconnect} disabled={busy}>
                  {t("unblock")}
                </button>
              </div>
            </div>
          )}

          <div className={`readouts ${live ? "" : "resting"}`}>
            <div className="readout down">
              <span className="readout-label">
                {Icon.down()}
                {t("download")}
              </span>
              <strong className="ltr">{live && traffic ? formatSpeed(traffic.downSpeed) : "—"}</strong>
              <span className="readout-sub ltr">{live && traffic ? formatBytes(traffic.downTotal) : " "}</span>
              <Spark value={traffic?.downSpeed ?? 0} active={live} />
            </div>
            <div className="readout up">
              <span className="readout-label">
                {Icon.up()}
                {t("upload")}
              </span>
              <strong className="ltr">{live && traffic ? formatSpeed(traffic.upSpeed) : "—"}</strong>
              <span className="readout-sub ltr">{live && traffic ? formatBytes(traffic.upTotal) : " "}</span>
              <Spark value={traffic?.upSpeed ?? 0} active={live} />
            </div>
            <button
              className={`readout delay ${!live ? "" : !health ? "checking" : health.ok ? "ok" : "failed"}`}
              onClick={checkHealth}
              disabled={!live}
              title={live ? t("checkAgain") : undefined}
            >
              <span className="readout-label">
                {Icon.bolt()}
                {t("latency")}
              </span>
              <strong>{!live ? "—" : !health ? t("checking") : health.ok ? <span className="ltr">{health.ms} ms</span> : t("noTraffic")}</strong>
              <span className="readout-sub">{live && health?.ok ? t("working") : " "}</span>
            </button>
          </div>

          <Segmented
            className="modes"
            label={t("connection")}
            value={settings.mode}
            disabled={busy}
            options={modes.map((m) => ({ value: m.id, label: m.label, title: m.hint }))}
            onChange={changeMode}
          />

          {needsReconnect && live && (
            <button className="reconnect-chip" onClick={() => settings.selected && connect(settings.selected)}>
              {Icon.refresh()}
              {t("settingsChanged")}
            </button>
          )}

          {live && session && session.mode !== "tun" && (
            <div className="endpoints">
              <button className="endpoint" onClick={() => copy(`127.0.0.1:${session.httpPort}`)}>
                <span>HTTP</span>
                <span className="ltr">127.0.0.1:{session.httpPort}</span> {Icon.copy()}
              </button>
              <button className="endpoint" onClick={() => api.socksUrl().then(copy, (e) => toast("error", String(e)))}>
                <span>SOCKS</span>
                <span className="ltr">127.0.0.1:{session.socksPort}</span> {Icon.copy()}
              </button>
            </div>
          )}
        </main>

        <div className="minibar" {...inert(!deckOpen)}>
          <span className="mini-dot" aria-hidden="true" />
          <span className="mini-text">
            <strong>{word}</strong>
            <span>{serverName}</span>
          </span>
          {live && session && <span className="clock ltr">{formatDuration(now - session.startedAt)}</span>}
          <button className="mini-power" onClick={togglePower} disabled={busy} aria-label={powerLabel} title={powerLabel}>
            {Icon.power(17)}
          </button>
        </div>

        <section className="deck" aria-label={t("servers")}>
          <button className="deck-grip" onClick={() => setDeckOpen((o) => !o)} aria-expanded={deckOpen} aria-label={t("servers")}>
            <span />
          </button>

          <div className="deck-head">
            <div className="deck-peek" {...inert(deckOpen)}>
              {profiles.length === 0 ? (
                <>
                  <span className="peek-text">
                    <strong>{t("noServers")}</strong>
                    <span>{t("noServersHint")}</span>
                  </span>
                  <button className="btn primary" onClick={openAdd}>
                    {Icon.plus()}
                    {t("add")}
                  </button>
                </>
              ) : (
                <button className="peek-open" onClick={() => setDeckOpen(true)}>
                  {selected && <ProtocolBadge protocol={selected.protocol} />}
                  <span className="peek-text">
                    <strong>{serverName}</strong>
                    <span>
                      {t("servers")} · <span className="ltr">{profiles.length}</span>
                      {selectedGroup ? ` · ${groupName(selectedGroup)}` : ""}
                    </span>
                  </span>
                  {selected && <Latency value={delays[selected.id]} />}
                  <span className="peek-chevron">{Icon.chevronUp()}</span>
                </button>
              )}
            </div>

            <div className="deck-bar" {...inert(!deckOpen)}>
              <h2>{t("servers")}</h2>
              <div className="deck-actions">
                <button
                  className={`icon-btn ${sortByDelay ? "toggled" : ""}`}
                  onClick={() => setSortByDelay((s) => !s)}
                  aria-label={t("sortByDelay")}
                  title={t("sortByDelay")}
                >
                  {Icon.sort()}
                </button>
                <button className="btn" onClick={testGroup} disabled={testing || !groupProfiles.length} title={t("testHint")}>
                  {Icon.bolt()}
                  {testing ? t("testing") : t("test")}
                </button>
                <button className="btn primary" onClick={openAdd}>
                  {Icon.plus()}
                  {t("add")}
                </button>
              </div>
            </div>
          </div>

          <div className="deck-body" {...inert(!deckOpen)}>
            <div className="tabs" role="tablist" aria-label={t("servers")} ref={strip} onWheel={onTabsWheel}>
              <span className="tab-marker" ref={marker} aria-hidden="true" />
              {groups.map((g) => (
                <button
                  key={g.id}
                  data-key={g.id}
                  role="tab"
                  aria-selected={g.id === activeGroup}
                  className={`tab ${g.id === activeGroup ? "active" : ""}`}
                  onClick={() => setActiveGroup(g.id)}
                >
                  {g.subscription && <span className="tab-dot" aria-hidden="true" />}
                  {groupName(g)}
                  <span className="tab-count ltr">{counts[g.id] ?? 0}</span>
                </button>
              ))}
            </div>

            <div className="deck-scroll" ref={deckScroll} onWheel={onDeckWheel} onScroll={() => (lastDeckScroll.current = Date.now())}>
              {group && (
                <div className="group-bar">
                  <div className="group-info">
                    {sub ? (
                      <>
                        <span>
                          {sub.updatedAt ? `${t("updated")} ${timeAgo(sub.updatedAt, t)}` : t("neverUpdated")}
                          {sub.expire ? ` · ${expiryText(sub.expire)}` : ""}
                        </span>
                        {sub.total ? (
                          <span className="usage">
                            <span className="usage-bar">
                              <i style={{ width: `${Math.min(100, (((sub.upload ?? 0) + (sub.download ?? 0)) / sub.total) * 100)}%` }} />
                            </span>
                            <span className="ltr">
                              {formatBytes((sub.upload ?? 0) + (sub.download ?? 0))} / {formatBytes(sub.total)}
                            </span>
                          </span>
                        ) : null}
                        {sub.url.startsWith("http:") && <span className="group-error warn">{t("httpSubscription")}</span>}
                        {sub.lastError && <span className="group-error">{sub.lastError}</span>}
                      </>
                    ) : (
                      <span>
                        {counts[group.id] ?? 0} {t("serversCount")}
                      </span>
                    )}
                  </div>
                  {sub && (
                    <button
                      className={`icon-btn ${updating === group.id ? "spinning" : ""}`}
                      onClick={() => updateSubscription(group.id)}
                      disabled={!!updating}
                      aria-label={t("updateNow")}
                      title={t("updateNow")}
                    >
                      {Icon.refresh()}
                    </button>
                  )}
                  <button className="icon-btn" onClick={() => setSheet("group")} aria-label={t("edit")} title={t("edit")}>
                    {Icon.more()}
                  </button>
                </div>
              )}

              {groupProfiles.length > 4 && (
                <label className="search">
                  {Icon.search()}
                  <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("searchServers")} />
                </label>
              )}

              {groupProfiles.length === 0 ? (
                <div className="empty">
                  {Icon.server()}
                  <p>{sub ? t("emptySubscription") : t("noServers")}</p>
                  <span>{sub ? t("emptySubscriptionHint") : t("noServersHint")}</span>
                  {!sub && (
                    <button className="btn primary" onClick={openAdd}>
                      {Icon.plus()}
                      {t("addServer")}
                    </button>
                  )}
                </div>
              ) : (
                <ul className="server-list" key={activeGroup}>
                  {visible.map((p, i) => {
                    const isSelected = p.id === settings.selected;
                    const isLive = live && session?.profileId === p.id;
                    return (
                      <li key={p.id} style={{ "--n": Math.min(i, 10) } as React.CSSProperties}>
                        <button className={`server ${isSelected ? "selected" : ""} ${isLive ? "live" : ""}`} onClick={() => select(p.id)}>
                          <ProtocolBadge protocol={p.protocol} />
                          <span className="server-info">
                            <span className="server-name">{p.name}</span>
                            <span className="server-meta ltr">
                              {p.stream.network}
                              {p.stream.security !== "none" && ` · ${p.stream.security}`}
                              {p.insecure && (
                                <span
                                  className="insecure"
                                  title={t(p.insecure === "unencrypted" ? "insecureUnencrypted" : "insecureUnverified")}
                                  aria-label={t(p.insecure === "unencrypted" ? "insecureUnencrypted" : "insecureUnverified")}
                                >
                                  {Icon.alert()}
                                </span>
                              )}
                            </span>
                          </span>
                          <Latency value={delays[p.id]} />
                        </button>
                        {!sub && (
                          <button className="icon-btn danger row-delete" onClick={() => remove(p.id)} aria-label={`${t("deleteServer")} ${p.name}`}>
                            {Icon.trash()}
                          </button>
                        )}
                      </li>
                    );
                  })}
                  {visible.length === 0 && (
                    <li className="no-match">
                      {t("noMatch")} “{query}”
                    </li>
                  )}
                </ul>
              )}
            </div>
          </div>
        </section>

        <Presence show={sheet === "settings" || sheet === "split"}>
          <SettingsSheet
            settings={settings}
            status={status}
            about={about}
            busy={busy}
            needsReconnect={needsReconnect && live}
            covered={sheet === "split"}
            onChange={changeSettings}
            onModeChange={changeMode}
            onReconnect={() => settings.selected && connect(settings.selected)}
            onOpenSplit={() => setSheet("split")}
            onClose={() => setSheet(null)}
          />
        </Presence>

        <Presence show={sheet === "split"}>
          <SplitSheet
            value={settings.split}
            connectionMode={settings.mode}
            onChange={async (split) => {
              const saved = await saveSettings({ ...settings, split });
              if (saved && live) setNeedsReconnect(true);
              return saved;
            }}
            onBack={() => setSheet("settings")}
          />
        </Presence>

        <Presence show={sheet === "info"}>
          <InfoSheet connected={live} language={settings.language} onClose={() => setSheet(null)} onCopy={copy} />
        </Presence>

        <Presence show={sheet === "logs"}>
          <Sheet
            title={t("logs")}
            onClose={() => setSheet(null)}
            actions={
              <div className="head-actions">
                <button className="btn small" onClick={() => copy(logs.join("\n"))} disabled={!logs.length}>
                  {t("copy")}
                </button>
                <button className="btn small" onClick={() => api.clearLogs().then(() => setLogs([]))} disabled={!logs.length}>
                  {t("clear")}
                </button>
              </div>
            }
          >
            <div
              className="logs"
              ref={logBox}
              onScroll={(e) => {
                const el = e.currentTarget;
                logFollow.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
              }}
            >
              {logs.length ? (
                logs.map((line, i) => (
                  <div key={i} className={`log-line ${logTag(line)}`}>
                    {line}
                  </div>
                ))
              ) : (
                <div className="log-empty">{t("noLogs")}</div>
              )}
            </div>
            <p className="hint">{t("logsHint")}</p>
          </Sheet>
        </Presence>

        <Presence show={sheet === "add"}>
          <AddSheet
            initialKind={addPreset.kind}
            initialText={addPreset.text}
            groups={groups}
            defaultGroupId={activeGroup}
            onAddLinks={addLinks}
            onAddSubscription={addSubscription}
            onCreateGroup={createGroup}
            onClose={() => setSheet(null)}
          />
        </Presence>

        <Presence show={sheet === "group"}>
          {group && <GroupSheet group={group} count={counts[group.id] ?? 0} onSave={saveGroup} onDelete={deleteGroup} onClose={() => setSheet(null)} />}
        </Presence>

        <Presence show={sheet === "admin"}>
          <Sheet dialog title={t("adminTitle")} onClose={() => setSheet(null)}>
            <p className="lead">{t("adminText")}</p>
            <div className="sheet-actions stacked">
              <button className="btn primary" onClick={() => api.relaunchAsAdmin().catch((e) => toast("error", String(e)))}>
                {Icon.shield()}
                {t("restartAsAdmin")}
              </button>
              {settings.mode === "tun" && !settings.killSwitch && (
                <button
                  className="btn"
                  onClick={async () => {
                    setSheet(null);
                    if ((await saveSettings({ ...settings, mode: "system" })) && settings.selected) connect(settings.selected);
                  }}
                >
                  {t("useSystemProxy")}
                </button>
              )}
            </div>
          </Sheet>
        </Presence>

        <Presence show={sheet === "quit"}>
          <Sheet dialog title={t("quitTitle")} onClose={() => setSheet(null)}>
            <p className="lead">{session ? t("quitText") : t("quitTextBlocked")}</p>
            <div className="sheet-actions stacked">
              <button className="btn danger" onClick={() => api.quitApp().catch((e) => toast("error", String(e)))}>
                {t("quit")}
              </button>
              <button
                className="btn"
                onClick={() => {
                  setSheet(null);
                  api.hideWindow().catch(() => {});
                }}
              >
                {t("minimizeToTray")}
              </button>
              <button className="btn ghost" onClick={() => setSheet(null)}>
                {t("cancel")}
              </button>
            </div>
          </Sheet>
        </Presence>

        <div className="toasts" aria-live="polite">
          {toasts.map((x) => (
            <div key={x.id} className={`toast ${x.kind}`} onClick={() => setToasts((all) => all.filter((y) => y.id !== x.id))}>
              {x.text}
            </div>
          ))}
        </div>
      </div>
    </I18n.Provider>
  );
}
