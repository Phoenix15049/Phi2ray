import { createContext, ReactNode, useContext, useEffect, useLayoutEffect, useRef, useState } from "react";
import type { Profile } from "./api";
import { T, useT } from "./i18n";

/** A server's delay: milliseconds, null for failed, "testing" while running, undefined if never tested. */
export type Delay = number | null | "testing" | undefined;

const svg = (children: ReactNode, size = 18) => (
  <svg
    viewBox="0 0 24 24"
    width={size}
    height={size}
    fill="none"
    stroke="currentColor"
    strokeWidth="1.7"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    {children}
  </svg>
);

export const Icon = {
  power: (size?: number) =>
    svg(
      <>
        <path d="M12 3v8" />
        <path d="M6.6 6.6a8 8 0 1 0 10.8 0" />
      </>,
      size,
    ),
  plus: () => svg(<path d="M12 5v14M5 12h14" />, 16),
  bolt: () => svg(<path d="M13 2 4 14h7l-1 8 9-12h-7z" />, 16),
  search: () =>
    svg(
      <>
        <circle cx="11" cy="11" r="7" />
        <path d="m20 20-3.5-3.5" />
      </>,
      16,
    ),
  settings: () =>
    svg(
      <>
        <path d="M4 7h10M18 7h2M4 17h2M10 17h10" />
        <circle cx="16" cy="7" r="2" />
        <circle cx="8" cy="17" r="2" />
      </>,
    ),
  terminal: () =>
    svg(
      <>
        <path d="m5 8 4 4-4 4M12 16h7" />
        <rect x="2" y="3" width="20" height="18" rx="3" />
      </>,
    ),
  trash: () => svg(<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3" />, 16),
  close: () => svg(<path d="M6 6l12 12M18 6 6 18" />),
  copy: () =>
    svg(
      <>
        <rect x="9" y="9" width="11" height="11" rx="2" />
        <path d="M5 15V5a1 1 0 0 1 1-1h9" />
      </>,
      13,
    ),
  sort: () => svg(<path d="M7 4v16M3 16l4 4 4-4M17 20V4M13 8l4-4 4 4" />, 16),
  shield: () => svg(<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z" />),
  globe: () =>
    svg(
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M3 12h18M12 3c2.5 3 2.5 15 0 18M12 3c-2.5 3-2.5 15 0 18" />
      </>,
    ),
  plug: () => svg(<path d="M9 2v6M15 2v6M6 8h12v3a6 6 0 0 1-12 0zM12 17v5" />),
  check: () => svg(<path d="m5 12 5 5 9-10" />, 16),
  refresh: () => svg(<path d="M20 11a8 8 0 0 0-14.6-4.5L4 8M4 4v4h4M4 13a8 8 0 0 0 14.6 4.5L20 16M20 20v-4h-4" />, 16),
  more: () =>
    svg(
      <>
        <circle cx="5" cy="12" r="1" />
        <circle cx="12" cy="12" r="1" />
        <circle cx="19" cy="12" r="1" />
      </>,
      16,
    ),
  lock: () =>
    svg(
      <>
        <rect x="5" y="11" width="14" height="10" rx="2" />
        <path d="M8 11V7a4 4 0 0 1 8 0v4" />
      </>,
      12,
    ),
  down: () => svg(<path d="M12 4v15M6 13l6 6 6-6" />, 14),
  split: (size?: number) => svg(<path d="M4 12h6l4-6h6M14 18h6M10 12l4 6M17 3l3 3-3 3M17 15l3 3-3 3" />, size),
  alert: () => svg(<path d="M12 4 2.5 20h19zM12 10v4.5M12 17.5h.01" />, 12),
  info: () =>
    svg(
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 11v5M12 7.5h.01" />
      </>,
    ),
  chevron: () => svg(<path d="m9 6 6 6-6 6" />, 16),
  chevronUp: () => svg(<path d="m6 15 6-6 6 6" />, 16),
  back: () => svg(<path d="M19 12H5M11 6l-6 6 6 6" />),
  minimize: () => svg(<path d="M6 12h12" />, 14),
  windowClose: () => svg(<path d="M7 7l10 10M17 7 7 17" />, 14),
  up: () => svg(<path d="M12 20V5M6 11l6-6 6 6" />, 14),
  server: () =>
    svg(
      <>
        <rect x="3" y="4" width="18" height="7" rx="2" />
        <rect x="3" y="13" width="18" height="7" rx="2" />
        <path d="M7 7.5h.01M7 16.5h.01" />
      </>,
      28,
    ),
};

/** How long a closing page or dialog stays on screen; matches the exit animations in styles.css. */
const EXIT_MS = 240;

const Closing = createContext(false);

/** Keeps its children on screen while they animate out. */
export function Presence({ show, children }: { show: boolean; children: ReactNode }) {
  const [mounted, setMounted] = useState(show);
  useEffect(() => {
    if (show) return setMounted(true);
    const timer = setTimeout(() => setMounted(false), EXIT_MS);
    return () => clearTimeout(timer);
  }, [show]);
  if (!show && !mounted) return null;
  return <Closing.Provider value={!show}>{children}</Closing.Provider>;
}

/** A full page sliding over the stage, or (`dialog`) a small card for one quick decision. */
export function Sheet(props: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  actions?: ReactNode;
  dialog?: boolean;
  /** Another page lies on top of this one, so Escape belongs to that one. */
  covered?: boolean;
  /** Stays under the header, for page-wide navigation. */
  subhead?: ReactNode;
}) {
  const t = useT();
  const closing = useContext(Closing);
  useEffect(() => {
    if (props.covered) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && props.onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [props.onClose, props.covered]);

  const state = closing ? "closing" : "open";
  if (props.dialog) {
    return (
      <div className="scrim" data-state={state} onClick={props.onClose}>
        <div className="dialog" role="dialog" aria-modal="true" aria-label={props.title} onClick={(e) => e.stopPropagation()}>
          <div className="dialog-head">
            <h2>{props.title}</h2>
            {props.actions}
            <button className="icon-btn" onClick={props.onClose} aria-label={t("cancel")}>
              {Icon.close()}
            </button>
          </div>
          <div className="dialog-body">{props.children}</div>
        </div>
      </div>
    );
  }
  return (
    <div className={`page ${props.covered ? "covered" : ""}`} data-state={state} role="dialog" aria-label={props.title}>
      <div className="page-head">
        <button className="icon-btn flip" onClick={props.onClose} aria-label={t("back")} title={t("back")}>
          {Icon.back()}
        </button>
        <h2>{props.title}</h2>
        {props.actions}
      </div>
      {props.subhead}
      <div className="page-body">{props.children}</div>
    </div>
  );
}

export function Switch(props: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button
      role="switch"
      aria-checked={props.checked}
      aria-label={props.label}
      className={`switch ${props.checked ? "on" : ""}`}
      onClick={() => props.onChange(!props.checked)}
    >
      <span />
    </button>
  );
}

/** A compact segmented control; the thumb slides to the chosen option. */
export function Segmented<V extends string>(props: {
  value: V;
  options: { value: V; label: string; title?: string }[];
  onChange: (v: V) => void;
  disabled?: boolean;
  label: string;
  className?: string;
}) {
  const index = props.options.findIndex((o) => o.value === props.value);
  const vars = { "--n": props.options.length, "--i": Math.max(0, index) } as React.CSSProperties;
  return (
    <div className={`segmented ${props.className ?? ""}`} role="radiogroup" aria-label={props.label} style={vars}>
      <span className="segmented-thumb" aria-hidden="true" />
      {props.options.map((o) => (
        <button
          key={o.value}
          role="radio"
          aria-checked={props.value === o.value}
          className={props.value === o.value ? "active" : ""}
          onClick={() => props.onChange(o.value)}
          disabled={props.disabled}
          title={o.title}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

/** Scrolls a strip sideways to an item, without moving anything around it. */
export function revealInStrip(strip: HTMLElement | null, item: Element | null | undefined) {
  if (!strip || !(item instanceof HTMLElement)) return;
  strip.scrollTo({ left: item.offsetLeft - (strip.clientWidth - item.offsetWidth) / 2, behavior: "smooth" });
}

/** Keeps a sliding marker under the active child of a scrolling strip. */
export function useSlidingMarker(active: string, deps: unknown[]) {
  const strip = useRef<HTMLDivElement>(null);
  const marker = useRef<HTMLSpanElement>(null);
  useLayoutEffect(() => {
    const place = () => {
      const el = strip.current?.querySelector<HTMLElement>(`[data-key="${CSS.escape(active)}"]`);
      if (!el || !marker.current) return;
      marker.current.style.width = `${el.offsetWidth}px`;
      marker.current.style.transform = `translateX(${el.offsetLeft}px)`;
    };
    place();
    const resize = new ResizeObserver(place);
    if (strip.current) resize.observe(strip.current);
    document.fonts?.ready.then(place);
    return () => resize.disconnect();
  }, [active, ...deps]);
  return { strip, marker };
}

export function Latency({ value }: { value: Delay }) {
  const t = useT();
  if (value === undefined) return null;
  if (value === "testing") {
    return (
      <span className="latency testing" aria-label={t("testing")}>
        <i />
        <i />
        <i />
      </span>
    );
  }
  if (value === null) return <span className="latency bad">{t("failed")}</span>;
  const level = value < 400 ? "good" : value < 1000 ? "mid" : "slow";
  const bars = value < 400 ? 3 : value < 1000 ? 2 : 1;
  return (
    <span className={`latency ${level}`}>
      <span className="bars" aria-hidden="true">
        {[1, 2, 3].map((b) => (
          <i key={b} className={b <= bars ? "lit" : ""} />
        ))}
      </span>
      <span className="ltr">{value} ms</span>
    </span>
  );
}

/** The last readings of a value, as a small line. */
export function Spark({ value, active }: { value: number; active: boolean }) {
  const [points, setPoints] = useState<number[]>([]);
  useEffect(() => {
    if (!active) return setPoints([]);
    setPoints((p) => [...p.slice(-31), value]);
  }, [value, active]);
  if (points.length < 2) return <svg className="spark" viewBox="0 0 100 24" preserveAspectRatio="none" aria-hidden="true" />;
  const peak = Math.max(...points, 1);
  const line = points.map((v, i) => `${100 - (points.length - 1 - i) * (100 / 31)},${22 - (v / peak) * 20}`).join(" ");
  return (
    <svg className="spark" viewBox="0 0 100 24" preserveAspectRatio="none" aria-hidden="true">
      <polyline points={line} vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

const PROTOCOL_LABEL: Record<Profile["protocol"], string> = {
  vless: "VL",
  vmess: "VM",
  trojan: "TR",
  shadowsocks: "SS",
};

export function ProtocolBadge({ protocol }: { protocol: Profile["protocol"] }) {
  return <span className={`proto proto-${protocol}`}>{PROTOCOL_LABEL[protocol]}</span>;
}

export function formatBytes(bytes: number) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value < 10 && unit > 0 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

export const formatSpeed = (bytesPerSecond: number) => `${formatBytes(bytesPerSecond)}/s`;

export function timeAgo(ms: number, t: T) {
  const minutes = Math.round((Date.now() - ms) / 60_000);
  if (minutes < 1) return t("justNow");
  if (minutes < 60) return `${minutes} ${t("minAgo")}`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} ${t("hAgo")}`;
  return `${Math.round(hours / 24)} ${t("dAgo")}`;
}

const regionNames: Record<string, Intl.DisplayNames | null> = {};

export function countryName(code: string, lang: string) {
  try {
    regionNames[lang] ??= new Intl.DisplayNames([lang], { type: "region" });
    return regionNames[lang]?.of(code.toUpperCase()) ?? code;
  } catch {
    return code;
  }
}

export function formatDuration(ms: number) {
  const s = Math.max(0, Math.floor(ms / 1000));
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(Math.floor(s / 3600))}:${pad(Math.floor((s % 3600) / 60))}:${pad(s % 60)}`;
}
