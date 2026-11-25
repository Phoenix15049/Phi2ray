import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { About, ADMIN_REQUIRED, api, DEFAULT_GROUP, DelayResult, Group, LibraryKind, Mode, onEvent, Profile, Settings, Status } from "./api";
import logo from "./assets/logo.svg";
import { useDeck } from "./deck";
import { DEFAULT_SETTINGS } from "./defaults";
import { AddKind, AddSheet, GroupSheet, LibraryDialog, looksLikeSubscription } from "./GroupSheets";
import { I18n, makeT, StringKey } from "./i18n";
import { InfoSheet } from "./InfoSheet";
import { LibraryMenu, MenuAction } from "./LibraryMenu";
import { useReorder } from "./reorder";
import { canDropImport, importFileError, readDroppedImport } from "./dropImport";
import { Iris, Rays, RayState } from "./Rays";
import { absoluteStatusLabel, modeOptions, SettingsSheet } from "./SettingsSheet";
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
type SheetName = "add" | "settings" | "split" | "info" | "logs" | "admin" | "group" | "quit" | "absolute" | "settings-absolute" | "library" | null;
type LibraryTarget = { kind: LibraryKind; id: string; name: string };
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
  "connectTimeout",
  "absoluteBrowserLocation",
  "version",
  "killSwitch",
  "absoluteTimezone",
  "autoReconnect",
  "language",
  "theme",
  "alwaysOnTop",
  "minimizeToTray",
  "logLines",
  "console",
];

/** `inert` takes hidden parts of the stage and deck out of the tab order. */
const inert = (on: boolean) => (on ? ({ inert: "" } as object) : {});

/** The part of the app a log line came from, for its colour. */
const logTag = (line: string) => (line.startsWith("[app]") ? "app" : line.startsWith("[console]") ? "app" : line.startsWith("[tun]") ? "tun" : line.startsWith("[xray]") ? "xray" : "");

/** Whether the system is set to dark, followed live for the "system" theme. */
function usePrefersDark() {
  const [dark, setDark] = useState(() => window.matchMedia("(prefers-color-scheme: dark)").matches);
  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const update = () => setDark(media.matches);
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);
  return dark;
}

const EMPTY_STATUS: Status = {
  absoluteSupported: false,
  absolute: { phase: "off", timezone: null, exitIp: null, error: null, locationBlocked: false, browserLocationPolicy: false },
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
  const confirmedSettings = useRef<Settings>(DEFAULT_SETTINGS);
  const settingsWrites = useRef(Promise.resolve());
  const settingsPending = useRef(0);
  const stateRead = useRef(0);
  const [status, setStatus] = useState<Status>(EMPTY_STATUS);
  const [pending, setPending] = useState<"connecting" | "disconnecting" | null>(null);
  const [needsReconnect, setNeedsReconnect] = useState(false);
  const [activeGroup, setActiveGroup] = useState(DEFAULT_GROUP);
  const [updating, setUpdating] = useState<string | null>(null);
  const [delays, setDelays] = useState<Record<string, Delay>>({});
  const [testing, setTesting] = useState(false);
  const [query, setQuery] = useState("");
  const [menu, setMenu] = useState<(LibraryTarget & { x: number; y: number; opener: HTMLElement; closing?: boolean }) | null>(null);
  const [libraryAction, setLibraryAction] = useState<(LibraryTarget & { action: "rename" | "delete" | "export"; opener: HTMLElement }) | null>(null);
  const [dropOver, setDropOver] = useState(false);
  const [sheet, setSheet] = useState<SheetName>(null);
  const absoluteOpener = useRef<HTMLElement | null>(null);
  const shell = useRef<HTMLDivElement>(null);
  const deck = useDeck(shell);
  const prefersDark = usePrefersDark();
  const [addPreset, setAddPreset] = useState<{ kind: AddKind; text: string; dropped?: boolean }>({ kind: "links", text: "" });
  const [logs, setLogs] = useState<string[]>([]);
  const [about, setAbout] = useState<About | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [now, setNow] = useState(Date.now());
  const pendingRef = useRef(pending);
  pendingRef.current = pending;
  const hadSession = useRef(false);
  const logBox = useRef<HTMLDivElement>(null);
  const logFollow = useRef(true);

  const t = useMemo(() => makeT(settings.language), [settings.language]);
  const tRef = useRef(t);
  tRef.current = t;

  const session = status.session;
  const phase: Phase = pending ?? (session ? session.state : "idle");
  const busy = pending !== null;
  const live = phase === "connected" || phase === "reconnecting";
  const dark = settings.theme === "dark" || (settings.theme === "system" && prefersDark);

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
    const request = ++stateRead.current;
    const s = await api.getState();
    if (request !== stateRead.current) return s;
    setGroups(s.groups);
    setProfiles(s.profiles);
    if (!settingsPending.current) {
      confirmedSettings.current = s.settings;
      setSettings(s.settings);
    }
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
      return true;
    } catch (e) {
      toast("error", String(e));
      return false;
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
    const load = () =>
      api
        .getLogs()
        .then((next) => setLogs((now) => (now.length === next.length && now[now.length - 1] === next[next.length - 1] ? now : next)))
        .catch(() => {});
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

  useEffect(() => {
    let active = true;
    let drop = 0;
    const hover = (event: DragEvent) => {
      if (!canDropImport(event.dataTransfer)) return;
      event.preventDefault();
      event.dataTransfer!.dropEffect = sheet ? "none" : "copy";
      if (!sheet) setDropOver(true);
    };
    const leave = (event: DragEvent) => {
      if (!event.relatedTarget) setDropOver(false);
    };
    const importDrop = async (event: DragEvent) => {
      const data = event.dataTransfer;
      if (!data || !canDropImport(data)) return;
      event.preventDefault();
      setDropOver(false);
      if (sheet) return;
      const current = ++drop;
      try {
        const text = await readDroppedImport(data);
        if (!active || current !== drop) return;
        if (!text) { toast("error", tRef.current("dropEmpty")); return; }
        setMenu((current) => current ? { ...current, closing: true } : null);
        setAddPreset({ kind: looksLikeSubscription(text) ? "subscription" : "links", text, dropped: true });
        setSheet("add");
      } catch (error) {
        if (active && current === drop) toast("error", tRef.current(importFileError(error)));
      }
    };
    window.addEventListener("dragover", hover);
    window.addEventListener("dragleave", leave);
    window.addEventListener("drop", importDrop);
    return () => {
      active = false;
      window.removeEventListener("dragover", hover);
      window.removeEventListener("dragleave", leave);
      window.removeEventListener("drop", importDrop);
    };
  }, [sheet, toast]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const p of profiles) c[p.groupId] = (c[p.groupId] ?? 0) + 1;
    return c;
  }, [profiles]);

  // Escape folds the deck away (a page or dialog on top takes it first).
  const { snap, go: deckGo } = deck;
  useEffect(() => {
    if (!snap || sheet) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && deckGo(0);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [snap, sheet, deckGo]);

  const saveSettings = (patch: Partial<Settings>) => {
    settingsPending.current++;
    setSettings((current) => ({ ...current, ...patch }));
    const result = settingsWrites.current.then(async () => {
      try {
        const saved = await api.updateSettings(patch);
        confirmedSettings.current = saved;
        if (settingsPending.current === 1) setSettings(saved);
        return true;
      } catch (e) {
        const saved = await api.getState().catch(() => null);
        if (saved) confirmedSettings.current = saved.settings;
        if (settingsPending.current === 1) setSettings(confirmedSettings.current);
        handleConnectError(e);
        return false;
      } finally {
        settingsPending.current--;
      }
    });
    settingsWrites.current = result.then(() => {});
    return result;
  };

  const togglePower = () => {
    if (busy) return;
    if (live) return disconnect();
    const id = profiles.find((p) => p.id === settings.selected)?.id ?? profiles[0]?.id;
    return id ? connect(id) : openAdd();
  };

  const select = async (id: string) => {
    if (busy) return;
    const saved = await saveSettings({ selected: id });
    if (saved && live && session?.profileId !== id) connect(id);
  };

  const changeMode = async (mode: Mode) => {
    if (busy || mode === settings.mode) return;
    const saved = await saveSettings({ mode });
    if (saved && live && settings.selected) connect(settings.selected);
  };

  const changeSettings = async (patch: Partial<Settings>) => {
    const absoluteChange = "absoluteMode" in patch || ("absoluteTimezone" in patch && settings.absoluteMode);
    const wasLive = live;
    if (absoluteChange) setPending(patch.absoluteMode === false ? "disconnecting" : "connecting");
    const saved = await saveSettings(patch);
    if (absoluteChange) {
      try {
        await refreshStatus().catch(() => {});
        if (saved && (patch.absoluteMode === true || wasLive)) {
          const id = profiles.find((p) => p.id === settings.selected)?.id ?? profiles[0]?.id;
          if (id) await connect(id);
        }
      } finally { setPending(null); }
      return;
    }
    const needsRestart = (Object.keys(patch) as (keyof Settings)[]).some((k) => !LIVE_SETTINGS.includes(k));
    if (saved && live && needsRestart) setNeedsReconnect(true);
    if (saved && "killSwitch" in patch) refreshStatus().catch(() => {});
  };

  const openAdd = async () => {
    let preset: { kind: AddKind; text: string } = { kind: "links", text: "" };
    try {
      const clip = (await navigator.clipboard.readText()).trim();
      if (looksLikeSubscription(clip)) preset = { kind: "subscription", text: clip };
      else if (clip.startsWith("{") || clip.startsWith("[") || clip.includes("://") || /^\s*\[Interface\]/im.test(clip) || /^[A-Za-z0-9+/=_-]{40,}$/.test(clip)) preset = { kind: "links", text: clip };
    } catch {
      // Clipboard access can be denied; the user can paste manually.
    }
    setAddPreset(preset);
    setSheet("add");
  };

  const addLinks = async (text: string, groupId: string, newGroupName?: string) => {
    try {
      const r = await api.importLinks(text, groupId, newGroupName);
      if (r.added) {
        await reload();
        setActiveGroup(r.groupId);
        deckGo(1);
        toast("info", `${t("added")}: ${r.added}`);
      }
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

  const deleteGroup = async (id = activeGroup) => {
    try {
      const inUse = profiles.some((p) => p.groupId === id && p.id === session?.profileId);
      if (inUse && !await disconnect()) return false;
      await api.deleteGroup(id);
      if (id === activeGroup) setActiveGroup(DEFAULT_GROUP);
      await reload();
      return true;
    } catch (e) {
      toast("error", String(e));
      return false;
    }
  };

  const remove = async (id: string) => {
    if (session?.profileId === id && !await disconnect()) return false;
    try {
      await api.deleteProfile(id);
      await reload();
      setDelays((previous) => Object.fromEntries(Object.entries(previous).filter(([key]) => key !== id)));
      return true;
    } catch (e) {
      toast("error", String(e));
      return false;
    }
  };

  const groupProfiles = useMemo(() => profiles.filter((p) => p.groupId === activeGroup), [profiles, activeGroup]);

  const testProfiles = async (ids: string[]) => {
    if (testing || !ids.length) return;
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

  const changeLibrary = async (action: () => Promise<unknown>) => {
    try {
      await action();
      await reload();
      return true;
    } catch (error) {
      toast("error", String(error));
      return false;
    }
  };

  const closeMenu = () => setMenu((current) => current && !current.closing ? { ...current, closing: true } : current);
  useEffect(() => {
    if (sheet) setMenu((current) => current && !current.closing ? { ...current, closing: true } : current);
  }, [sheet]);

  const openMenu = (target: LibraryTarget, opener: HTMLElement, point?: { x: number; y: number }) => {
    const rect = opener.getBoundingClientRect();
    const anchor = { x: settings.language === "fa" ? rect.right : rect.left, y: rect.bottom + 4 };
    setMenu({ ...target, opener, ...(point ?? anchor) });
  };

  const contextProps = (target: LibraryTarget) => ({
    onContextMenu: (event: React.MouseEvent<HTMLElement>) => {
      event.preventDefault();
      openMenu(target, event.currentTarget, event.clientX || event.clientY ? { x: event.clientX, y: event.clientY } : undefined);
    },
    onKeyDown: (event: React.KeyboardEvent<HTMLElement>) => {
      if (event.key === "ContextMenu" || (event.shiftKey && event.key === "F10")) {
        event.preventDefault();
        openMenu(target, event.currentTarget);
      }
    },
  });

  /** Vertical wheel scrolls the tab strip sideways. */
  const onTabsWheel = (e: React.WheelEvent<HTMLDivElement>) => {
    if (Math.abs(e.deltaY) > Math.abs(e.deltaX)) e.currentTarget.scrollLeft += settings.language === "fa" ? -e.deltaY : e.deltaY;
  };

  /** The wheel over the stage moves the deck, unless the stage itself has to scroll. */
  const onStageWheel = (e: React.WheelEvent<HTMLElement>) => {
    const el = e.currentTarget;
    if (snap > 0 || el.scrollHeight <= el.clientHeight + 1) deck.onWheel(e);
  };

  /** A click on an empty part of the stage folds the deck back down. */
  const foldDeck = (e: React.MouseEvent) => {
    if (snap > 0 && !(e.target as Element).closest("button")) deckGo(0);
  };

  const group = groups.find((g) => g.id === activeGroup);
  const sortByDelay = !!group?.sortByDelay;
  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = q
      ? groupProfiles.filter((p) => `${p.name} ${p.address} ${p.protocol} ${p.stream.network}`.toLowerCase().includes(q))
      : groupProfiles;
    const rank = (d: Delay) => typeof d === "number" ? d : Number.MAX_SAFE_INTEGER;
    return [...list].sort((a, b) =>
      Number(b.starred) - Number(a.starred) || (sortByDelay ? rank(delays[a.id]) - rank(delays[b.id]) : 0)
    );
  }, [groupProfiles, query, sortByDelay, delays]);

  const tabList = useRef<HTMLDivElement>(null);
  const serverList = useRef<HTMLUListElement>(null);
  const groupOrder = useReorder(groups, tabList, tabList, "x", !!sheet || !snap,
    (id, target) => changeLibrary(() => api.moveLibraryItem("group", id, false, target)));
  const rowOrder = useReorder(visible, serverList, deck.list, "y", !!sheet || !snap || sortByDelay || !!query.trim(),
    (id, target) => changeLibrary(() => api.moveLibraryItem("profile", id, false, target)));
  const { marker } = useSlidingMarker(activeGroup, [groupOrder.visible, counts, settings.language], tabList);
  useEffect(() => {
    revealInStrip(tabList.current, tabList.current?.querySelector(".tab-item:has(.tab.active)"));
  }, [activeGroup, groups.length, snap]);

  const selected = profiles.find((p) => p.id === settings.selected);
  const sub = group?.subscription;
  const health = session?.health;
  const traffic = session?.traffic;
  const unhealthy = phase === "connected" && health && !health.ok;
  const blocked = status.blocked && !session && !busy;
  const absoluteWaiting = blocked && settings.absoluteMode && !status.absolute.error;
  const rayState: RayState = blocked ? "blocked" : unhealthy || phase === "reconnecting" ? "warning" : phase;
  // Apps can only be split in VPN mode; sites in every mode.
  const split = settings.split;
  const splitActive = !settings.absoluteMode && split.enabled && (split.sites.length > 0 || (settings.mode === "tun" && split.apps.length > 0));
  const modes = modeOptions(t);

  // The built-in group keeps its translated name until the user renames it.
  const groupName = (g: Group) => (g.id === DEFAULT_GROUP && g.name === "My servers" ? t("myServers") : g.name);
  const menuActions = (): MenuAction[] => {
    if (!menu) return [];
    const confirm = (action: "rename" | "delete" | "export") => () => {
      setLibraryAction({ ...menu, action });
      setSheet("library");
    };
    const targetedGroup = groups.find((g) => g.id === menu.id);
    const profile = profiles.find((p) => p.id === menu.id);
    const siblings = menu.kind === "group" ? groups : profiles.filter((p) => p.groupId === profile?.groupId && p.starred === profile?.starred);
    const index = siblings.findIndex((item) => item.id === menu.id);
    if (index < 0) return [];
    const autoOrder = menu.kind === "profile" && groups.some((g) => g.id === profile?.groupId && g.sortByDelay);
    const move = (earlier: boolean) => () => { void changeLibrary(() => api.moveLibraryItem(menu.kind, menu.id, earlier)); };
    const actions: MenuAction[] = [{ label: t("renameItem"), icon: Icon.edit(), run: confirm("rename") }];
    if (menu.kind === "group" && targetedGroup) {
      const ids = profiles.filter((p) => p.groupId === menu.id).map((p) => p.id);
      if (targetedGroup.subscription) actions.push({ label: t("updateNow"), icon: Icon.refresh(), run: () => void updateSubscription(menu.id), disabled: !!updating });
      actions.push(
        { label: t("test"), icon: Icon.bolt(), run: () => void testProfiles(ids), disabled: testing || !ids.length },
        { label: t(targetedGroup.sortByDelay ? "manualOrder" : "sortByDelay"), icon: Icon.sort(), run: () => void changeLibrary(() => api.setGroupSort(menu.id, !targetedGroup.sortByDelay)) },
      );
    } else if (profile) {
      actions.push(
        { label: t("testOne"), icon: Icon.bolt(), run: () => void testProfiles([profile.id]), disabled: testing },
        { label: t(profile.starred ? "unstarItem" : "starItem"), icon: Icon.star(profile.starred), run: () => void changeLibrary(() => api.updateProfile(profile.id, { starred: !profile.starred })) },
      );
    }
    actions.push(
      { label: t("exportConfigs"), icon: Icon.copy(), run: confirm("export"), disabled: menu.kind === "group" && !counts[menu.id] },
      { label: t(menu.kind === "group" ? "moveEarlier" : "moveUp"), icon: Icon.up(), run: move(true), disabled: autoOrder || index === 0 },
      { label: t(menu.kind === "group" ? "moveLater" : "moveDown"), icon: Icon.down(), run: move(false), disabled: autoOrder || index === siblings.length - 1 },
      { label: t(menu.kind === "group" ? "deleteGroup" : "deleteServer"), icon: Icon.trash(), run: confirm("delete"), danger: true, disabled: busy || menu.id === DEFAULT_GROUP },
    );
    return actions;
  };

  const selectedGroup = groups.find((g) => g.id === selected?.groupId);

  const expiryText = (expireSeconds: number) => {
    const days = Math.ceil((expireSeconds * 1000 - Date.now()) / 86_400_000);
    if (days < 0) return t("expired");
    if (days === 0) return t("expiresToday");
    return `${days} ${t("daysLeft")}`;
  };

  const logLines = useMemo(
    () =>
      logs.map((line, i) => (
        <div key={i} className={`log-line ${logTag(line)}`}>
          {line}
        </div>
      )),
    [logs],
  );

  const word = absoluteWaiting ? t("absoluteWaiting") : blocked ? t("blockedTitle") : unhealthy ? t("noInternet") : t(PHASE_LABEL[phase]);
  const serverName = selected ? selected.name : t("noServerSelected");
  const powerLabel = live ? t("disconnect") : t("connect");
  const absolutePhase = status.absolute.error ? "error" : settings.absoluteMode ? status.absolute.phase : "off";
  const absoluteLabel = t(absoluteStatusLabel(absolutePhase));
  const absoluteDialog = sheet === "absolute" || sheet === "settings-absolute";
  const openAbsolute = (fromSettings: boolean) => {
    absoluteOpener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setSheet(fromSettings ? "settings-absolute" : "absolute");
  };
  const absoluteDialogBack = () => setSheet(sheet === "settings-absolute" ? "settings" : null);
  const absoluteDisable = settings.absoluteMode || !!status.absolute.error;
  const absoluteAction = t(absoluteDisable ? "absoluteDisable" : "absoluteEnable");

  return (
    <I18n.Provider value={t}>
      <div className="shell" ref={shell} data-phase={rayState} data-snap={snap}>
        <header className="titlebar" data-tauri-drag-region {...inert(!!sheet)}>
          <span className="mark" data-tauri-drag-region>
            <img src={logo} alt="" aria-hidden="true" data-tauri-drag-region />
            Phi2ray
          </span>
          <div className="title-tools">
            <button className="icon-btn" onClick={() => setSheet("info")} aria-label={t("connectionInfo")} title={t("connectionInfo")}>
              {Icon.globe()}
            </button>
            {status.absoluteSupported && (
              <button className="icon-btn absolute-tool" data-phase={absolutePhase} aria-haspopup="dialog"
                onClick={() => openAbsolute(false)} disabled={busy} aria-label={absoluteAction} title={absoluteLabel}>
                {Icon.shield(16)}
              </button>
            )}
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

        <main className="stage" onWheel={onStageWheel} onClick={foldDeck} {...inert(!!sheet || snap === 2)}>
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
              {(settings.absoluteMode || status.absolute.error || (live && (status.firewall || splitActive))) && (
                <span className="seals">
                  {(settings.absoluteMode || status.absolute.error) && (
                    <span className="absolute-seal" data-phase={absolutePhase} title={absoluteLabel} aria-label={absoluteLabel}>
                      {Icon.shield(12)}
                    </span>
                  )}
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
              paused={snap === 2 || sheet === "settings" || sheet === "split" || sheet === "info" || sheet === "logs"}
              light={!dark}
            />
            <span className="field-end near">{t("thisPc")}</span>
            {live && session?.exit && (
              <button className="field-end far" onClick={() => setSheet("info")} title={t("whatSitesSee")}>
                <strong>{session.exit.country ? countryName(session.exit.country, settings.language) : t("infoInternet")}</strong>
                <span className="ltr">{session.exit.ip}</span>
              </button>
            )}
            <button className="lens" onClick={togglePower} disabled={busy} aria-label={powerLabel} title={powerLabel}>
              <Iris phase={rayState} />
            </button>
          </div>

          <div className="stage-low" {...inert(snap > 0)}>
          {blocked && (
            <div className={`alert ${absoluteWaiting ? "warn" : "danger"}`}>
              <span>{t(status.absolute.error ? "absoluteError" : absoluteWaiting ? "absoluteWaitingHint" : "blockedBanner")}</span>
              <div className="alert-actions">
                <button className="btn small primary" onClick={togglePower}>
                  {t(!profiles.length ? "add" : absoluteWaiting ? "connect" : "reconnect")}
                </button>
                <button className="btn small" onClick={settings.absoluteMode || status.absolute.error ? () => setSheet("settings") : disconnect} disabled={busy}>
                  {t(settings.absoluteMode || status.absolute.error ? "settings" : "unblock")}
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
            value={settings.absoluteMode ? "tun" : settings.mode}
            disabled={busy || settings.absoluteMode}
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
          </div>
        </main>

        <div className="minibar" onClick={foldDeck} {...inert(!!sheet || snap !== 2)}>
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

        <section className="deck" aria-label={t("servers")} {...inert(!!sheet)}>
          <div className="deck-top" onWheel={deck.onWheel} {...deck.dragProps}>
          <button className="deck-grip" onClick={() => deckGo(snap === 1 ? 2 : 1)} aria-expanded={snap > 0} aria-label={t("servers")}>
            <span />
          </button>

          <div className="deck-head">
            <div className="deck-peek" {...inert(snap > 0)}>
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
                <button className="peek-open" onClick={() => deckGo(1)}>
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

            <div className="deck-bar" {...inert(snap === 0)}>
              <h2>{t("servers")}</h2>
              <div className="deck-actions">
                <button
                  className={`icon-btn ${sortByDelay ? "toggled" : ""}`}
                  onClick={() => { if (group) void changeLibrary(() => api.setGroupSort(group.id, !sortByDelay)); }}
                  disabled={!group}
                  aria-pressed={sortByDelay}
                  aria-label={t("sortByDelay")}
                  title={t("sortByDelay")}
                >
                  {Icon.sort()}
                </button>
                <button className="btn" onClick={() => testProfiles(groupProfiles.map((p) => p.id))} disabled={testing || !groupProfiles.length} title={t("testHint")}>
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

          </div>

          <div className="deck-body" {...inert(snap === 0)}>
            <div className="tabs" role="tablist" aria-label={t("servers")} ref={tabList} onWheel={onTabsWheel} {...groupOrder.pointer}>
              <span className="tab-marker" ref={marker} aria-hidden="true" />
              {groupOrder.visible.map((g) => (
                <div className="tab-item" role="presentation" key={g.id} data-key={g.id} data-sort-id={g.id}
                  data-dragging={groupOrder.dragging === g.id || undefined}>
                <button type="button" className="reorder-handle tab-handle"
                  aria-label={`${t("reorderGroup")} · ${groupName(g)}`} title={t("reorderGroup")}
                  {...groupOrder.handle(g.id)}>{Icon.grip()}</button>
                <button
                  role="tab"
                  aria-selected={g.id === activeGroup}
                  className={`tab ${g.id === activeGroup ? "active" : ""}`}
                  onClick={() => setActiveGroup(g.id)}
                  aria-haspopup="menu"
                  {...contextProps({ kind: "group", id: g.id, name: groupName(g) })}
                >
                  {g.subscription && <span className="tab-dot" aria-hidden="true" />}
                  {groupName(g)}
                  <span className="tab-count ltr">{counts[g.id] ?? 0}</span>
                </button>
                </div>
              ))}
            </div>

            <div className="deck-scroll" ref={deck.list} onWheel={deck.onListWheel} onScroll={deck.onListScroll}>
              {group && (
                <div className="group-bar" onContextMenu={(event) => {
                  event.preventDefault();
                  const opener = event.currentTarget.querySelector<HTMLButtonElement>(".group-menu");
                  if (opener) openMenu({ kind: "group", id: group.id, name: groupName(group) }, opener, { x: event.clientX, y: event.clientY });
                }}>
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
                  {sub && <button className="icon-btn" onClick={() => setSheet("group")} aria-label={t("edit")} title={t("edit")}>{Icon.edit()}</button>}
                  <button className="icon-btn group-menu" aria-haspopup="menu" aria-label={t("groupActions")} title={t("groupActions")}
                    onClick={(event) => openMenu({ kind: "group", id: group.id, name: groupName(group) }, event.currentTarget)}>
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
                <ul className="server-list" key={activeGroup} ref={serverList} {...rowOrder.pointer}>
                  {rowOrder.visible.map((p) => {
                    const isSelected = p.id === settings.selected;
                    const isLive = live && session?.profileId === p.id;
                    const target: LibraryTarget = { kind: "profile", id: p.id, name: p.name };
                    return (
                      <li key={p.id} className="server-row" data-sort-id={p.id}
                        data-dragging={rowOrder.dragging === p.id || undefined}
                        data-menu-open={menu?.kind === "profile" && menu.id === p.id && !menu.closing || undefined}
                        onContextMenu={(event) => {
                          event.preventDefault();
                          const opener = event.currentTarget.querySelector<HTMLButtonElement>(".server");
                          if (opener) openMenu(target, opener, { x: event.clientX, y: event.clientY });
                        }}>
                        <button type="button" className="reorder-handle row-handle"
                          aria-label={`${t("reorderServer")} · ${p.name}`}
                          title={t(sortByDelay ? "reorderSorted" : query.trim() ? "reorderFiltered" : "reorderServer")}
                          {...rowOrder.handle(p.id)}>{Icon.grip()}</button>
                        <button className={`server ${isSelected ? "selected" : ""} ${isLive ? "live" : ""}`} onClick={() => select(p.id)}
                          aria-haspopup="menu" onKeyDown={contextProps(target).onKeyDown}>
                          <ProtocolBadge protocol={p.protocol} />
                          <span className="server-info">
                            <span className="server-name-line">
                              {p.starred && <span className="server-star" title={t("starredItem")} aria-label={t("starredItem")}>{Icon.star(true)}</span>}
                              <span className="server-name" dir="auto">{p.name}</span>
                            </span>
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
                        <button className="icon-btn row-menu" aria-haspopup="menu" aria-label={`${t("profileActions")} · ${p.name}`} title={t("profileActions")}
                          onClick={(event) => openMenu(target, event.currentTarget)} onKeyDown={contextProps(target).onKeyDown}>
                          {Icon.more()}
                        </button>
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

        <Presence show={sheet === "settings" || sheet === "split" || sheet === "settings-absolute"}>
          <SettingsSheet
            settings={settings}
            status={status}
            about={about}
            busy={busy}
            needsReconnect={needsReconnect && live}
            covered={sheet === "split" || sheet === "settings-absolute"}
            onChange={changeSettings}
            onAbsoluteToggle={() => openAbsolute(true)}
            onModeChange={changeMode}
            onReconnect={() => settings.selected && connect(settings.selected)}
            onOpenSplit={() => setSheet("split")}
            onClose={() => setSheet(null)}
          />
        </Presence>

        <Presence show={sheet === "split"}>
          <SplitSheet
            value={settings.split}
            connectionMode={settings.absoluteMode ? "tun" : settings.mode}
            onChange={async (split) => {
              const saved = await saveSettings({ split });
              if (saved && live) setNeedsReconnect(true);
              return saved;
            }}
            onBack={() => setSheet("settings")}
          />
        </Presence>

        <Presence show={sheet === "info"}>
          <InfoSheet key={session ? `${session.profileId}-${session.startedAt}-${session.reconnects}` : "offline"}
            connected={!!session} absolute={settings.absoluteMode} language={settings.language} onClose={() => setSheet(null)} onCopy={copy} />
        </Presence>

        <Presence show={absoluteDialog}>
          <Sheet dialog title={t(absoluteDisable ? "absoluteDisableTitle" : "absoluteEnableTitle")} onClose={absoluteDialogBack}
            returnFocusTo={absoluteOpener.current}>
            <p className="lead">{t(absoluteDisable ? "absoluteDisableText" : "absoluteEnableText")}</p>
            <div className="sheet-actions">
              <button className="btn" onClick={absoluteDialogBack}>{t("cancel")}</button>
              <button className={absoluteDisable ? "btn danger" : "btn primary"} disabled={busy} onClick={() => {
                absoluteDialogBack();
                void changeSettings({ absoluteMode: !absoluteDisable });
              }}>{absoluteAction}</button>
            </div>
          </Sheet>
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
                logLines
              ) : (
                <div className="log-empty">{t("noLogs")}</div>
              )}
            </div>
            <p className="hint">{t("logsHint")}</p>
          </Sheet>
        </Presence>

        {menu && <LibraryMenu {...menu} closing={menu.closing || !!sheet} label={menu.name} actions={menuActions()} onClose={closeMenu}
          onExit={() => setMenu((current) => current === menu ? null : current)} />}
        {dropOver && !sheet && <div className="drop-import-overlay" aria-hidden="true">
          <span>{Icon.down()}{t("dropImportTitle")}</span>
        </div>}

        <Presence show={sheet === "library"}>
          {libraryAction && <LibraryDialog key={`${libraryAction.id}-${libraryAction.action}`}
            {...libraryAction} count={libraryAction.kind === "group" ? counts[libraryAction.id] ?? 0 : undefined}
            onClose={() => setSheet(null)} onConfirm={async (name) => {
              const { kind, id, action } = libraryAction;
              if (action === "delete") return kind === "group" ? deleteGroup(id) : remove(id);
              if (action === "rename") return changeLibrary(() => kind === "group" ? api.updateGroup(id, name) : api.updateProfile(id, { name }));
              try {
                const clipboard = navigator.clipboard;
                if (typeof ClipboardItem === "function" && typeof clipboard.write === "function") {
                  // WebKit requires the clipboard write to begin within the click gesture.
                  const content = api.exportLibraryItem(kind, id).then((text) => new Blob([text], { type: "text/plain" }));
                  await clipboard.write([new ClipboardItem({ "text/plain": content })]);
                } else {
                  await clipboard.writeText(await api.exportLibraryItem(kind, id));
                }
                toast("info", t("copied"));
                return true;
              } catch (error) {
                toast("error", error instanceof DOMException ? t("clipboardFailed") : String(error));
                return false;
              }
            }} />}
        </Presence>

        <Presence show={sheet === "add"}>
          <AddSheet
            initialKind={addPreset.kind}
            initialText={addPreset.text}
            dropped={addPreset.dropped}
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
              {!settings.absoluteMode && settings.mode === "tun" && !settings.killSwitch && (
                <button
                  className="btn"
                  onClick={async () => {
                    setSheet(null);
                    if ((await saveSettings({ mode: "system" })) && settings.selected) connect(settings.selected);
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
