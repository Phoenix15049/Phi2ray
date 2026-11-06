import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { mock } from "./mock";

export type Mode = "tun" | "system" | "manual";

export type Profile = {
  id: string;
  name: string;
  protocol: "vless" | "vmess" | "trojan" | "shadowsocks";
  address: string;
  port: number;
  groupId: string;
  stream: { network: string; security: string };
  /** Not encrypted to the server, or its TLS certificate isn't checked. */
  insecure: "unencrypted" | "unverified" | null;
};

export type Subscription = {
  url: string;
  autoUpdate: boolean;
  intervalHours: number;
  updatedAt: number | null;
  lastError: string | null;
  upload: number | null;
  download: number | null;
  total: number | null;
  /** Unix seconds. */
  expire: number | null;
};

export type Group = {
  id: string;
  name: string;
  subscription: Subscription | null;
};

export const DEFAULT_GROUP = "default";

export type SplitTunnel = {
  enabled: boolean;
  /** exclude: listed apps/sites skip the VPN. include: only they use it. */
  mode: "exclude" | "include";
  apps: string[];
  sites: string[];
};

export type RunningApp = { name: string; path: string };

export type Settings = {
  version: number;
  mode: Mode;
  selected: string | null;
  autoConnect: boolean;
  killSwitch: boolean;
  autoReconnect: boolean;
  bypassLan: boolean;
  iranDirect: boolean;
  blockAds: boolean;
  blockQuic: boolean;
  split: SplitTunnel;
  remoteDns: string;
  ipv6: boolean;
  tunStack: "mixed" | "system" | "gvisor";
  tunMtu: number;
  strictRoute: boolean;
  fixedPorts: boolean;
  socksPort: number;
  httpPort: number;
  logLevel: "warning" | "info" | "debug";
  testUrl: string;
  language: "en" | "fa";
  theme: "system" | "light" | "dark";
  alwaysOnTop: boolean;
  minimizeToTray: boolean;
  /** The `phi2ray` console command. */
  console: boolean;
};

export type Health = { ok: boolean; ms: number | null; checkedAt: number };

/** Bytes per second and session totals through the server. */
export type Traffic = { upSpeed: number; downSpeed: number; upTotal: number; downTotal: number };

export type Session = {
  profileId: string;
  mode: Mode;
  socksPort: number;
  httpPort: number;
  startedAt: number;
  state: "connected" | "reconnecting";
  health: Health | null;
  exit: { ip: string; country: string | null } | null;
  reconnects: number;
  killSwitch: boolean;
  traffic: Traffic;
};

export type Status = {
  session: Session | null;
  firewall: boolean;
  blocked: boolean;
  xrayFound: boolean;
  tunFound: boolean;
  elevated: boolean;
  /** Why the bundled cores couldn't be unpacked (single-exe builds). */
  coreError: string | null;
};

export type About = {
  app: string;
  xray: string | null;
  singBox: string | null;
  coreDir: string;
  dataDir: string;
};

/** One geolocation database's view of an IP. */
export type Geo = {
  source: string;
  ip: string | null;
  country: string | null;
  region: string | null;
  city: string | null;
  asn: string | null;
  org: string | null;
  proxy: boolean | null;
  error: string | null;
};

/** Looked up on request only, always through the server. */
export type ConnectionInfo = {
  exit: Geo[];
  trace: { ip: string; country: string | null; colo: string | null } | null;
  /** Where the connection enters: the server address xray dials. */
  entry: { address: string; ip: string; public: boolean; geo: Geo[] } | null;
  checkedAt: number;
};

export type DelayResult = { id: string; ms: number | null };
export type SubscriptionResult = { groupId: string; count: number; skipped: number };

/** Error text the backend returns when the chosen options need administrator rights. */
export const ADMIN_REQUIRED = "ADMIN_REQUIRED";

export type Backend = {
  call<T>(cmd: string, args?: Record<string, unknown>): Promise<T>;
  on<T>(event: string, cb: (payload: T) => void): Promise<() => void>;
};

const tauri: Backend = {
  call<T>(cmd: string, args?: Record<string, unknown>) {
    return invoke<T>(cmd, args);
  },
  on<T>(event: string, cb: (payload: T) => void) {
    return listen<T>(event, (e) => cb(e.payload));
  },
};

// Outside Tauri (plain `npm run dev` in a browser) use fake data, so the UI can be
// designed and tested without touching the network.
const backend: Backend = "__TAURI_INTERNALS__" in window || !import.meta.env.DEV ? tauri : mock;

export const api = {
  getState: () => backend.call<{ groups: Group[]; profiles: Profile[]; settings: Settings }>("get_state"),
  importLinks: (text: string, groupId: string) =>
    backend.call<{ added: number; errors: string[] }>("import_links", { text, groupId }),
  deleteProfile: (id: string) => backend.call<void>("delete_profile", { id }),
  createGroup: (name: string) => backend.call<string>("create_group", { name }),
  updateGroup: (id: string, name: string, url?: string, autoUpdate?: boolean) =>
    backend.call<void>("update_group", { id, name, url, autoUpdate }),
  deleteGroup: (id: string) => backend.call<void>("delete_group", { id }),
  addSubscription: (url: string) => backend.call<SubscriptionResult>("add_subscription", { url }),
  updateSubscription: (id: string) => backend.call<SubscriptionResult>("update_subscription", { id }),
  /** Returns the settings as saved (split tunnel entries cleaned up). */
  updateSettings: (settings: Settings) => backend.call<Settings>("update_settings", { settings }),
  runningApps: () => backend.call<RunningApp[]>("running_apps"),
  connect: (id: string) => backend.call<Session>("connect", { id }),
  disconnect: () => backend.call<void>("disconnect"),
  status: () => backend.call<Status>("status"),
  checkConnection: () => backend.call<Health>("check_connection"),
  connectionInfo: () => backend.call<ConnectionInfo>("connection_info"),
  /** The SOCKS link including its password; fetched only when the user copies it. */
  socksUrl: () => backend.call<string>("socks_url"),
  getLogs: () => backend.call<string[]>("get_logs"),
  clearLogs: () => backend.call<void>("clear_logs"),
  testDelays: (ids: string[] = []) => backend.call<void>("test_delays", { ids }),
  about: () => backend.call<About>("about"),
  relaunchAsAdmin: () => backend.call<void>("relaunch_as_admin"),
  pingDns: (servers: string[]) => backend.call<(number | null)[]>("ping_dns", { servers }),
  quitApp: () => backend.call<void>("quit_app"),
  hideWindow: () => backend.call<void>("hide_window"),
  minimizeWindow: () => backend.call<void>("minimize_window"),
  /** Like the title bar's close button: asks first while connected. */
  closeWindow: () => backend.call<void>("close_window"),
  /** Only the app's own fixed links ("github", "site"). */
  openLink: (name: "github" | "site") => backend.call<void>("open_link", { name }),
};

export const onEvent = <T,>(event: string, cb: (payload: T) => void) => backend.on<T>(event, cb);
