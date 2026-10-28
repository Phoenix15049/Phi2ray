import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { About, ADMIN_REQUIRED, api, DEFAULT_GROUP, DelayResult, Group, Mode, onEvent, Profile, Settings, Status } from "./api";
import logo from "./assets/logo.svg";
import { DEFAULT_SETTINGS } from "./defaults";
import { AddKind, AddSheet, GroupSheet, looksLikeSubscription } from "./GroupSheets";
import { I18n, makeT, StringKey } from "./i18n";
import { InfoSheet } from "./InfoSheet";
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
  ProtocolBadge,
  Segmented,
  Sheet,
  timeAgo,
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
  const [addPreset, setAddPreset] = useState<{ kind: AddKind; text: string }>({ kind: "links", text: "" });
  const [logs, setLogs] = useState<string[]>([]);
  const [about, setAbout] = useState<About | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [now, setNow] = useState(Date.now());
  const pendingRef = useRef(pending);
  pendingRef.current = pending;
  const hadSession = useRef(false);
  const logEnd = useRef<HTMLDivElement>(null);
  const tabsRef = useRef<HTMLDivElement>(null);

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

  useEffect(() => {
    if (sheet === "logs") logEnd.current?.scrollIntoView();
  }, [logs, sheet]);

  useEffect(() => {
    if (sheet === "settings") api.about().then(setAbout).catch(() => {});
  }, [sheet]);

  // Fall back to the default tab if the active group disappears.
  useEffect(() => {
    if (groups.length && !groups.some((g) => g.id === activeGroup)) setActiveGroup(DEFAULT_GROUP);
  }, [groups, activeGroup]);

  // Keep the active tab in view.
  useEffect(() => {
    tabsRef.current?.querySelector(".tab.active")?.scrollIntoView({ block: "nearest", inline: "nearest", behavior: "smooth" });
  }, [activeGroup, groups.length]);

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

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = q
      ? groupProfiles.filter((p) => `${p.name} ${p.address} ${p.protocol} ${p.stream.network}`.toLowerCase().includes(q))
      : groupProfiles;
    if (!sortByDelay) return list;
    const rank = (d: Delay) => (typeof d === "number" ? d : d === "testing" ? 1e6 : 1e7);
    return [...list].sort((a, b) => rank(delays[a.id]) - rank(delays[b.id]));
  }, [groupProfiles, query, sortByDelay, delays]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const p of profiles) c[p.groupId] = (c[p.groupId] ?? 0) + 1;
    return c;
  }, [profiles]);

  const selected = profiles.find((p) => p.id === settings.selected);
  const group = groups.find((g) => g.id === activeGroup);
  const sub = group?.subscription;
  const socksUrl = session && `socks5://${session.socksUser}:${session.socksPass}@127.0.0.1:${session.socksPort}`;
  const health = session?.health;
  const traffic = session?.traffic;
  const unhealthy = phase === "connected" && health && !health.ok;
  const heroClass = unhealthy || phase === "reconnecting" ? "warning" : phase;
  // Apps can only be split in VPN mode; sites in every mode.
  const split = settings.split;
  const splitActive = split.enabled && (split.sites.length > 0 || (settings.mode === "tun" && split.apps.length > 0));
  const modes = modeOptions(t);

  // The built-in group keeps its translated name until the user renames it.
  const groupName = (g: Group) => (g.id === DEFAULT_GROUP && g.name === "My servers" ? t("myServers") : g.name);

  const expiryText = (expireSeconds: number) => {
    const days = Math.ceil((expireSeconds * 1000 - Date.now()) / 86_400_000);
    if (days < 0) return t("expired");
    if (days === 0) return t("expiresToday");
    return `${days} ${t("daysLeft")}`;
  };

  return (
    <I18n.Provider value={t}>
      <div className="app">
        <header className="topbar">
          <div className="brand">
            <img className="logo" src={logo} alt="" aria-hidden="true" />
            <span>Phi2ray</span>
          </div>
          <div className="top-actions">
            <button className="icon-btn" onClick={() => setSheet("info")} aria-label={t("connectionInfo")} title={t("connectionInfo")}>
              {Icon.info()}
            </button>
            <button className="icon-btn" onClick={() => setSheet("logs")} aria-label={t("logs")} title={t("logs")}>
              {Icon.terminal()}
            </button>
            <button className="icon-btn" onClick={() => setSheet("settings")} aria-label={t("settings")} title={t("settings")}>
              {Icon.settings()}
            </button>
          </div>
        </header>

        {status.coreError ? (
          <div className="alert warn">
            {t("coreUnpackFailed")}
            <span className="alert-detail ltr">{status.coreError}</span>
          </div>
        ) : (
          !status.xrayFound && <div className="alert warn">{t("xrayMissing")}</div>
        )}
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

        <section className={`hero ${heroClass}`}>
          <div className="hero-main">
            <button className="power" onClick={togglePower} disabled={busy} aria-label={live ? t("disconnect") : t("connect")}>
              <span className="power-ring" aria-hidden="true" />
              {Icon.power(34)}
            </button>
            <div className="hero-status">
              <div className="status-line">
                <span className="status-title">{unhealthy ? t("noInternet") : t(PHASE_LABEL[phase])}</span>
                {live && session && <span className="timer ltr">{formatDuration(now - session.startedAt)}</span>}
              </div>
              <div className="status-sub">{selected ? selected.name : t("noServerSelected")}</div>
              {live && session && (
                <div className="hero-chips">
                  <button
                    className={`chip health ${!health ? "checking" : health.ok ? "ok" : "failed"}`}
                    onClick={checkHealth}
                    title={t("checkAgain")}
                  >
                    {!health ? t("checking") : health.ok ? <span className="ltr">{health.ms} ms</span> : t("noTraffic")}
                  </button>
                  {session.exit && (
                    <span className="chip" title={t("whatSitesSee")}>
                      {session.exit.country ? `${countryName(session.exit.country, settings.language)} · ` : ""}
                      <span className="ltr">{session.exit.ip}</span>
                    </span>
                  )}
                  {(status.firewall || splitActive) && (
                    <span className="chip accent icons">
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
                </div>
              )}
            </div>
          </div>

          {live && traffic && (
            <div className="stats">
              <div className="stat down">
                <span className="stat-icon">{Icon.down()}</span>
                <span className="stat-text">
                  <strong className="ltr">{formatSpeed(traffic.downSpeed)}</strong>
                  <span>
                    {t("download")} · <span className="ltr">{formatBytes(traffic.downTotal)}</span>
                  </span>
                </span>
              </div>
              <div className="stat up">
                <span className="stat-icon">{Icon.up()}</span>
                <span className="stat-text">
                  <strong className="ltr">{formatSpeed(traffic.upSpeed)}</strong>
                  <span>
                    {t("upload")} · <span className="ltr">{formatBytes(traffic.upTotal)}</span>
                  </span>
                </span>
              </div>
            </div>
          )}

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
              {t("settingsChanged")}
            </button>
          )}

          {live && session && session.mode !== "tun" && (
            <div className="endpoints">
              <button className="endpoint" onClick={() => copy(`127.0.0.1:${session.httpPort}`)}>
                <span>HTTP</span>
                <span className="ltr">127.0.0.1:{session.httpPort}</span> {Icon.copy()}
              </button>
              <button className="endpoint" onClick={() => copy(socksUrl!)}>
                <span>SOCKS</span>
                <span className="ltr">127.0.0.1:{session.socksPort}</span> {Icon.copy()}
              </button>
            </div>
          )}
        </section>

        <section className="servers">
          <div className="servers-head">
            <h2>{t("servers")}</h2>
            <div className="servers-actions">
              <button
                className={`icon-btn ${sortByDelay ? "toggled" : ""}`}
                onClick={() => setSortByDelay((s) => !s)}
                aria-label={t("sortByDelay")}
                title={t("sortByDelay")}
              >
                {Icon.sort()}
              </button>
              <button className="btn" onClick={testGroup} disabled={testing || !groupProfiles.length}>
                {Icon.bolt()}
                {testing ? t("testing") : t("test")}
              </button>
              <button className="btn primary" onClick={openAdd}>
                {Icon.plus()}
                {t("add")}
              </button>
            </div>
          </div>

          <div className="tabs" role="tablist" aria-label={t("servers")} ref={tabsRef} onWheel={onTabsWheel}>
            {groups.map((g) => (
              <button
                key={g.id}
                role="tab"
                aria-selected={g.id === activeGroup}
                className={`tab ${g.id === activeGroup ? "active" : ""}`}
                onClick={() => setActiveGroup(g.id)}
              >
                {g.subscription && <span className="tab-dot" aria-hidden="true" />}
                {groupName(g)}
                <span className="tab-count">{counts[g.id] ?? 0}</span>
              </button>
            ))}
          </div>

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
            <ul className="server-list">
              {visible.map((p) => {
                const isSelected = p.id === settings.selected;
                const isLive = live && session?.profileId === p.id;
                return (
                  <li key={p.id}>
                    <button className={`server ${isSelected ? "selected" : ""} ${isLive ? "live" : ""}`} onClick={() => select(p.id)}>
                      <ProtocolBadge protocol={p.protocol} />
                      <span className="server-info">
                        <span className="server-name">{p.name}</span>
                        <span className="server-meta ltr">
                          {p.stream.network}
                          {p.stream.security !== "none" && ` · ${p.stream.security}`}
                          {p.insecure && (
                            <span className="insecure" title={t("insecureServer")} aria-label={t("insecureServer")}>
                              {Icon.alert()}
                            </span>
                          )}
                        </span>
                      </span>
                      <Latency value={delays[p.id]} />
                    </button>
                    {!sub && (
                      <button className="icon-btn danger" onClick={() => remove(p.id)} aria-label={`${t("deleteServer")} ${p.name}`}>
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
        </section>

        {sheet === "add" && (
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
        )}

        {sheet === "group" && group && (
          <GroupSheet group={group} count={counts[group.id] ?? 0} onSave={saveGroup} onDelete={deleteGroup} onClose={() => setSheet(null)} />
        )}

        {sheet === "settings" && (
          <SettingsSheet
            settings={settings}
            status={status}
            about={about}
            busy={busy}
            needsReconnect={needsReconnect && live}
            onChange={changeSettings}
            onModeChange={changeMode}
            onReconnect={() => settings.selected && connect(settings.selected)}
            onOpenSplit={() => setSheet("split")}
            onClose={() => setSheet(null)}
          />
        )}

        {sheet === "split" && (
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
        )}

        {sheet === "info" && (
          <InfoSheet connected={live} language={settings.language} onClose={() => setSheet(null)} onCopy={copy} />
        )}

        {sheet === "logs" && (
          <Sheet
            title={t("logs")}
            onClose={() => setSheet(null)}
            actions={
              <div className="sheet-head-actions">
                <button className="btn small" onClick={() => copy(logs.join("\n"))} disabled={!logs.length}>
                  {t("copy")}
                </button>
                <button className="btn small" onClick={() => api.clearLogs().then(() => setLogs([]))} disabled={!logs.length}>
                  {t("clear")}
                </button>
              </div>
            }
          >
            <pre className="logs">
              {logs.length ? logs.join("\n") : t("noLogs")}
              <div ref={logEnd} />
            </pre>
            <p className="hint">{t("logsHint")}</p>
          </Sheet>
        )}

        {sheet === "admin" && (
          <Sheet title={t("adminTitle")} onClose={() => setSheet(null)}>
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
        )}

        {sheet === "quit" && (
          <Sheet title={t("quitTitle")} onClose={() => setSheet(null)}>
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
        )}

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
