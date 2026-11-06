// Fake backend for designing the UI in a normal browser. Never touches the network.
import { DEFAULT_SETTINGS } from "./defaults";
import type { Backend, Group, Profile, Session, Settings } from "./api";

type Listener = (payload: unknown) => void;

const listeners = new Map<string, Set<Listener>>();
const emit = (event: string, payload: unknown) => listeners.get(event)?.forEach((l) => l(payload));
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
const GB = 1024 ** 3;

let nextId = 1;
const make = (name: string, protocol: Profile["protocol"], network: string, security: string, groupId = "default"): Profile => ({
  id: String(nextId++),
  name,
  protocol,
  address: `server${nextId}.example.com`,
  port: 443,
  groupId,
  stream: { network, security },
  insecure: security === "none" && protocol !== "shadowsocks" ? "unencrypted" : null,
});

let groups: Group[] = [
  { id: "default", name: "My servers", subscription: null },
  {
    id: "sub1",
    name: "FastNet",
    subscription: {
      url: "https://panel.example.com/sub/abc",
      autoUpdate: true,
      intervalHours: 12,
      updatedAt: Date.now() - 2 * 3600_000,
      lastError: null,
      upload: 1.2 * GB,
      download: 31.6 * GB,
      total: 50 * GB,
      expire: Math.floor(Date.now() / 1000) + 23 * 86400,
    },
  },
];
let profiles: Profile[] = [
  make("🇩🇪 Germany · Reality", "vless", "tcp", "reality"),
  make("🇹🇷 Istanbul WS CDN", "vmess", "ws", "tls"),
  make("🇳🇱 Amsterdam XHTTP", "vless", "xhttp", "tls", "sub1"),
  make("🇫🇮 Helsinki gRPC", "vless", "grpc", "tls", "sub1"),
  make("🇺🇸 New York Trojan", "trojan", "tcp", "tls", "sub1"),
  make("🇬🇧 London SS", "shadowsocks", "tcp", "none", "sub1"),
  make("🇨🇦 Toronto plain", "vless", "ws", "none", "sub1"),
  make("🇫🇷 Paris Reality", "vless", "tcp", "reality", "sub1"),
];
// Screenshot helpers: ?demo=connected&lang=fa&theme=light starts the mock in that state.
const params = new URLSearchParams(location.search);
let settings: Settings = {
  ...DEFAULT_SETTINGS,
  selected: profiles[0].id,
  language: params.get("lang") === "fa" ? "fa" : "en",
  theme: (params.get("theme") as Settings["theme"]) ?? DEFAULT_SETTINGS.theme,
  split: params.get("split")
    ? { enabled: true, mode: "exclude", apps: ["Telegram.exe"], sites: ["digikala.com"] }
    : DEFAULT_SETTINGS.split,
};
let session: Session | null =
  params.get("demo") === "connected" || params.get("demo") === "reconnecting" || params.get("demo") === "nointernet"
    ? {
        profileId: profiles[0].id,
        mode: "tun",
        socksPort: 49731,
        httpPort: 50212,
        startedAt: Date.now() - 754_000,
        state: params.get("demo") === "reconnecting" ? "reconnecting" : "connected",
        health: { ok: params.get("demo") !== "nointernet", ms: params.get("demo") === "nointernet" ? null : 184, checkedAt: Date.now() },
        exit: { ip: "203.0.113.24", country: "DE" },
        reconnects: 0,
        killSwitch: true,
        traffic: { upSpeed: 96_000, downSpeed: 2_300_000, upTotal: 21_000_000, downTotal: 486_000_000 },
      }
    : null;
const logs: string[] = [];

const blocked = params.get("demo") === "blocked";
const mockStatus = () => ({ session, firewall: !!session?.killSwitch || blocked, blocked: blocked && !session, xrayFound: true, tunFound: true, elevated: true, coreError: null });

const handlers: Record<string, (args: Record<string, any>) => unknown> = {
  get_state: () => ({ groups, profiles, settings }),
  import_links: ({ text, groupId }) => {
    const links = String(text).split(/\s+/).filter((l) => l.includes("://"));
    profiles = [...profiles, ...links.map((_, i) => make(`Imported ${i + 1}`, "vless", "ws", "tls", groupId))];
    return { added: links.length, errors: [] };
  },
  delete_profile: ({ id }) => {
    profiles = profiles.filter((p) => p.id !== id);
  },
  create_group: ({ name }) => {
    const id = `g${nextId++}`;
    groups = [...groups, { id, name, subscription: null }];
    return id;
  },
  update_group: ({ id, name, url, autoUpdate }) => {
    groups = groups.map((g) =>
      g.id !== id
        ? g
        : {
            ...g,
            name,
            subscription: g.subscription && {
              ...g.subscription,
              url: url ?? g.subscription.url,
              autoUpdate: autoUpdate ?? g.subscription.autoUpdate,
            },
          },
    );
  },
  delete_group: ({ id }) => {
    groups = groups.filter((g) => g.id !== id);
    profiles = profiles.filter((p) => p.groupId !== id);
  },
  add_subscription: async ({ url }) => {
    await wait(1200);
    if (!String(url).startsWith("http")) throw "Subscription links must start with https:// or http://";
    const id = `g${nextId++}`;
    groups = [
      ...groups,
      {
        id,
        name: new URL(url).host,
        subscription: { url, autoUpdate: true, intervalHours: 12, updatedAt: Date.now(), lastError: null, upload: null, download: 0, total: null, expire: null },
      },
    ];
    profiles = [...profiles, make("Imported A", "vless", "ws", "tls", id), make("Imported B", "trojan", "tcp", "tls", id)];
    return { groupId: id, count: 2, skipped: 0 };
  },
  update_subscription: async ({ id }) => {
    await wait(1000);
    groups = groups.map((g) => (g.id === id && g.subscription ? { ...g, subscription: { ...g.subscription, updatedAt: Date.now() } } : g));
    return { groupId: id, count: profiles.filter((p) => p.groupId === id).length, skipped: 0 };
  },
  update_settings: ({ settings: s }) => {
    if (s.tunMtu < 1280 || s.tunMtu > 9000) throw "MTU must be between 1280 and 9000.";
    const bad = s.split.sites.find((x: string) => !/^[\w.:/-]+\.[\w.:/-]+$/.test(x.replace(/^https?:\/\//, "")));
    if (bad) throw `"${bad}" isn't a valid site, IP or IP range.`;
    const clean = (x: string) => x.toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0];
    settings = { ...s, split: { ...s.split, sites: [...new Set<string>(s.split.sites.map(clean))] } };
    return settings;
  },
  running_apps: async () => {
    await wait(300);
    return [
      { name: "Telegram.exe", path: "C:\\Users\\you\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe" },
      { name: "chrome.exe", path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" },
      { name: "steam.exe", path: "C:\\Program Files (x86)\\Steam\\steam.exe" },
      { name: "Code.exe", path: "C:\\Users\\you\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe" },
      { name: "Discord.exe", path: "C:\\Users\\you\\AppData\\Local\\Discord\\app-1.0.9\\Discord.exe" },
    ];
  },
  connect: async ({ id }) => {
    await wait(900);
    const port = () => 49152 + Math.floor(Math.random() * 10000);
    session = {
      profileId: id,
      mode: settings.mode,
      socksPort: settings.fixedPorts ? settings.socksPort : port(),
      httpPort: settings.fixedPorts ? settings.httpPort : port(),
      startedAt: Date.now(),
      state: "connected",
      health: null,
      exit: null,
      reconnects: 0,
      killSwitch: settings.killSwitch,
      traffic: { upSpeed: 0, downSpeed: 0, upTotal: 0, downTotal: 0 },
    };
    setTimeout(() => {
      if (session) session = { ...session, health: { ok: true, ms: 184, checkedAt: Date.now() }, exit: { ip: "2.59.135.114", country: "DE" } };
    }, 1500);
    logs.push("[app] Connecting (mock)", "[xray] Xray 26.10.21 started (mock)");
    return session;
  },
  disconnect: () => {
    session = null;
  },
  status: () => {
    if (session) {
      // Fake a busy connection so the speed display moves.
      const down = Math.round(200_000 + Math.random() * 2_400_000);
      const up = Math.round(20_000 + Math.random() * 180_000);
      const t = session.traffic;
      session = { ...session, traffic: { downSpeed: down, upSpeed: up, downTotal: t.downTotal + down, upTotal: t.upTotal + up } };
    }
    return mockStatus();
  },
  ping_dns: async ({ servers }) => {
    await wait(700);
    return (servers as string[]).map((s) => (s.startsWith("https") ? (Math.random() < 0.15 ? null : Math.round(40 + Math.random() * 250)) : null));
  },
  quit_app: () => {
    session = null;
    location.reload();
  },
  hide_window: () => {},
  minimize_window: () => {},
  close_window: () => emit("close-requested", null),
  open_link: () => {},
  socks_url: () => {
    if (!session) throw "Not connected.";
    return `socks5://mockuser:mockpass@127.0.0.1:${session.socksPort}`;
  },
  check_connection: async () => {
    await wait(400);
    const health = { ok: true, ms: Math.round(120 + Math.random() * 400), checkedAt: Date.now() };
    if (session) session = { ...session, health };
    return health;
  },
  connection_info: async () => {
    await wait(1100);
    if (!session) throw "Not connected.";
    // Documentation-range IPs: an entry relay in one country, the exit in another.
    const exit = { ip: "203.0.113.24", region: "Hesse", asn: "AS64500", org: "Example Hosting GmbH", proxy: null, latitude: 50.05, longitude: 8.7, error: null };
    return {
      exit: [
        { ...exit, source: "ipapi.co", country: "DE", city: "Neu-Isenburg" },
        { ...exit, source: "DB-IP", country: "DE", city: "Frankfurt am Main", asn: null, org: null, latitude: null, longitude: null },
        { ...exit, source: "FreeIPAPI", country: "DE", city: "Frankfurt am Main", proxy: false },
      ],
      trace: { ip: "203.0.113.24", country: "DE", colo: "FRA" },
      entry: {
        address: profiles.find((p) => p.id === session?.profileId)?.address ?? "server.example.com",
        ip: "198.51.100.7",
        public: true,
        geo: [
          { source: "ipapi.co", ip: "198.51.100.7", country: "AE", region: "Dubai", city: "Dubai", asn: "AS64501", org: "Example Telecom", proxy: null, latitude: 25.2, longitude: 55.3, error: null },
          { source: "FreeIPAPI", ip: null, country: null, region: null, city: null, asn: null, org: null, proxy: null, latitude: null, longitude: null, error: "Rate limited, try later" },
        ],
      },
      quality: {
        score: 50,
        vpn: true,
        proxy: false,
        tor: false,
        hosting: true,
        compromised: false,
        network: "Hosting",
        operator: null,
        blocklists: [
          { name: "Barracuda", listed: false },
          { name: "blocklist.de", listed: false },
          { name: "DroneBL", listed: false },
          { name: "SpamCop", listed: true },
          { name: "s5h", listed: null },
        ],
        error: null,
      },
      checkedAt: Date.now(),
    };
  },
  get_logs: () => [...logs],
  clear_logs: () => {
    logs.length = 0;
  },
  test_delays: async ({ ids }) => {
    const targets = ids.length ? profiles.filter((p) => ids.includes(p.id)) : profiles;
    await Promise.all(
      targets.map(async (p) => {
        await wait(300 + Math.random() * 1500);
        emit("delay", { id: p.id, ms: Math.random() < 0.2 ? null : Math.round(80 + Math.random() * 900) });
      }),
    );
  },
  about: () => ({
    app: "0.1.3",
    xray: "26.10.21",
    singBox: "1.14.4",
    coreDir: "C:\\Phi2ray\\core",
    dataDir: "C:\\Users\\you\\AppData\\Roaming\\com.phi2ray.app",
  }),
  relaunch_as_admin: () => {},
};

export const mock: Backend = {
  async call<T>(cmd: string, args: Record<string, unknown> = {}) {
    const handler = handlers[cmd];
    if (!handler) throw new Error(`mock: unknown command ${cmd}`);
    return (await handler(args)) as T;
  },
  async on<T>(event: string, cb: (payload: T) => void) {
    const set = listeners.get(event) ?? new Set<Listener>();
    set.add(cb as Listener);
    listeners.set(event, set);
    return () => {
      set.delete(cb as Listener);
    };
  },
};
