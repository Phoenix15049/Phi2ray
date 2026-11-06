import { useEffect, useRef } from "react";

export type RayState = "idle" | "connecting" | "connected" | "warning" | "disconnecting" | "blocked";

/** The lens sits on the golden section of the stage: 1 / φ² of the way across. */
export const LENS = 0.382;

type Rgb = [number, number, number];
const THISTLE: Rgb = [219, 194, 207];
const CERULEAN: Rgb = [111, 179, 194];
const AMBER: Rgb = [233, 190, 120];
const CORAL: Rgb = [232, 138, 138];

const mix = (a: Rgb, b: Rgb, t: number): Rgb => [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];
const rgba = (c: Rgb, alpha: number) => `rgba(${c[0] | 0},${c[1] | 0},${c[2] | 0},${alpha})`;

/** Bytes per second on a 0..1 scale that still moves at a few KB/s and tops out near 100 MB/s. */
const level = (bytes: number) => Math.min(1, Math.log10(1 + bytes / 1024) / 5);

/** What each state asks of the rays; the drawing eases towards these. */
const TARGET: Record<RayState, { reach: number; energy: number; warn: number; cut: number }> = {
  idle: { reach: 0, energy: 0.1, warn: 0, cut: 0 },
  connecting: { reach: 0.42, energy: 0.6, warn: 0, cut: 0 },
  connected: { reach: 1, energy: 0.62, warn: 0, cut: 0 },
  warning: { reach: 0.72, energy: 0.42, warn: 1, cut: 0 },
  disconnecting: { reach: 0, energy: 0.25, warn: 0, cut: 0 },
  blocked: { reach: 0, energy: 0.16, warn: 0, cut: 1 },
};

/**
 * Phi2ray's two rays: download and upload, weaving through the lens. They are the connection's
 * real state, not decoration. Behind the closed lens they stop; once it opens they reach across
 * the stage, and their weight, pace and the pulses along them follow the actual traffic.
 */
export function Rays(props: { state: RayState; down: number; up: number; mirror: boolean; paused: boolean }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const el = canvas.current;
    const ctx = el?.getContext("2d");
    if (!el || !ctx) return;

    const still = window.matchMedia("(prefers-reduced-motion: reduce)");
    let w = 0;
    let h = 0;
    const fit = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = el.clientWidth;
      h = el.clientHeight;
      el.width = Math.round(w * dpr);
      el.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    fit();
    const resize = new ResizeObserver(fit);
    resize.observe(el);

    const start = TARGET[live.current.state];
    const now = { ...start, down: 0, up: 0 };
    const pulses = [0, 1].map(() => Array.from({ length: 12 }, (_, i) => (i + Math.random() * 0.6) / 12));
    let time = Math.random() * 40;
    let phase = 0;
    let last = performance.now();
    let frame = 0;
    let tick = 0;

    const draw = (at: number) => {
      frame = requestAnimationFrame(draw);
      const { state, down, up, mirror, paused } = live.current;
      const resting = state === "idle" || state === "blocked";
      // Nothing to watch while hidden or covered, and a resting stage doesn't need every frame.
      if (document.hidden || paused || (resting && ++tick % 2 && now.reach < 0.01)) {
        last = at;
        return;
      }
      const dt = still.matches ? 1 : Math.min((at - last) / 1000, 0.05);
      last = at;

      const goal = TARGET[state];
      const ease = (from: number, to: number, rate: number) => from + (to - from) * (1 - Math.exp(-dt * rate));
      const liveTraffic = state === "connected" || state === "warning";
      now.down = ease(now.down, liveTraffic ? level(down) : 0, 3);
      now.up = ease(now.up, liveTraffic ? level(up) : 0, 3);
      const traffic = Math.max(now.down, now.up);
      const breathing = state === "connecting" ? 0.14 * Math.sin(time * 3.2) : 0;
      now.reach = ease(now.reach, goal.reach + breathing, state === "disconnecting" ? 5 : 2.6);
      now.energy = ease(now.energy, goal.energy + (state === "connected" ? 0.38 * traffic : 0), 3);
      now.warn = ease(now.warn, goal.warn, 3);
      now.cut = ease(now.cut, goal.cut, 3);

      if (!still.matches) {
        time += dt;
        phase += dt * (0.25 + 1.9 * now.energy + 1.2 * traffic);
      }

      ctx.save();
      ctx.clearRect(0, 0, w, h);
      if (mirror) {
        ctx.translate(w, 0);
        ctx.scale(-1, 1);
      }
      const lensX = w * LENS;
      const cy = h / 2;
      const front = lensX + now.reach * (w - lensX);
      const amplitude = Math.min(h * 0.3, 56) * (0.34 + 0.66 * now.energy);
      const pinch = Math.max(w * 0.09, 34);
      const wave = (2 * Math.PI) / (w * 0.5);
      const tremor = now.warn * 2.4;

      // Half a wave apart, so the two always weave around each other; a slow drift keeps it alive.
      const y = (x: number, offset: number) => {
        const d = (x - lensX) / pinch;
        const open = 1 - Math.exp(-d * d);
        const main = Math.sin(x * wave - phase + offset);
        const second = 0.2 * Math.sin(x * wave * 1.618 + phase * 0.6 + offset);
        const shake = tremor ? tremor * Math.sin(x * 0.11 + time * 19) : 0;
        return cy + amplitude * open * (main + second) + shake;
      };

      // The light gathering at the lens.
      ctx.globalCompositeOperation = "lighter";
      const glowColor = mix(mix(THISTLE, AMBER, now.warn), CORAL, now.cut);
      const glowSize = 70 + 90 * now.energy;
      const glow = ctx.createRadialGradient(lensX, cy, 0, lensX, cy, glowSize);
      glow.addColorStop(0, rgba(glowColor, 0.05 + 0.26 * now.energy));
      glow.addColorStop(1, rgba(glowColor, 0));
      ctx.fillStyle = glow;
      ctx.fillRect(lensX - glowSize, cy - glowSize, glowSize * 2, glowSize * 2);

      const drift = 0.5 * Math.sin(time * 0.31);
      const rays: { base: Rgb; offset: number; load: number; dir: number }[] = [
        // Download comes in from the far side; upload heads out.
        { base: THISTLE, offset: 0, load: now.down, dir: -1 },
        { base: CERULEAN, offset: Math.PI + drift, load: now.up, dir: 1 },
      ];

      rays.forEach((ray, i) => {
        const color = mix(mix(ray.base, AMBER, now.warn * 0.85), CORAL, now.cut * 0.9);
        const line = ctx.createLinearGradient(0, 0, w, 0);
        const nearAlpha = 0.28 + 0.62 * now.energy;
        const stop = (at: number, alpha: number) => line.addColorStop(Math.min(1, Math.max(0, at / w)), rgba(color, alpha));
        stop(0, 0);
        stop(lensX * 0.34, nearAlpha);
        stop(lensX, nearAlpha);
        if (now.reach > 0.004) {
          stop(lensX + 1, 0.3 + 0.65 * now.energy);
          stop(Math.max(lensX + 2, front - 46), 0.3 + 0.65 * now.energy);
          stop(front, front >= w - 1 ? 0.25 : 0);
        } else {
          stop(lensX + 1, 0);
        }
        stop(Math.min(w, front + 1), 0);

        ctx.beginPath();
        for (let x = 0; x <= front + 4; x += 5) {
          const py = y(x, ray.offset);
          if (x === 0) ctx.moveTo(x, py);
          else ctx.lineTo(x, py);
        }
        ctx.strokeStyle = line;
        ctx.lineCap = "round";
        ctx.lineJoin = "round";
        const weight = 1 + 0.9 * now.energy + 1.1 * ray.load;
        // A wide faint pass under the sharp line stands in for bloom at a fraction of the cost.
        ctx.globalAlpha = 0.09;
        ctx.lineWidth = weight * 6;
        ctx.stroke();
        ctx.globalAlpha = 1;
        ctx.lineWidth = weight;
        ctx.stroke();

        // Pulses: how many, and how fast, is the traffic in this direction.
        const list = pulses[i];
        const shown = Math.round(list.length * Math.min(1, 0.15 + ray.load * 1.5));
        if (now.reach > 0.3 && now.cut < 0.5) {
          for (let p = 0; p < list.length; p++) {
            list[p] += ray.dir * dt * (0.05 + 0.4 * ray.load);
            if (list[p] > 1) list[p] -= 1;
            if (list[p] < 0) list[p] += 1;
            if (p >= shown) continue;
            const x = list[p] * w;
            if (x > front) continue;
            const edge = Math.min(x / 40, (front - x) / 40, 1);
            ctx.fillStyle = rgba(mix(color, [255, 255, 255], 0.55), 0.9 * Math.max(0, edge));
            ctx.beginPath();
            ctx.arc(x, y(x, ray.offset), 1.2 + 1.1 * ray.load, 0, Math.PI * 2);
            ctx.fill();
          }
        }
      });
      ctx.restore();
    };
    frame = requestAnimationFrame(draw);
    return () => {
      cancelAnimationFrame(frame);
      resize.disconnect();
    };
  }, []);

  return <canvas ref={canvas} className="rays" aria-hidden="true" />;
}

/** The lens: an iris that shuts the rays out when disconnected and opens to let them through. */
export function Iris({ size = 104 }: { size?: number }) {
  const blades = 9;
  return (
    <svg className="iris" viewBox="-50 -50 100 100" width={size} height={size} aria-hidden="true">
      <defs>
        <clipPath id="iris-clip">
          <circle r="41" />
        </clipPath>
        <linearGradient id="iris-blade" x1="0" y1="-1" x2="1" y2="1">
          <stop offset="0" stopColor="#2E4756" />
          <stop offset="1" stopColor="#16262E" />
        </linearGradient>
      </defs>
      <circle className="iris-track" r="47" />
      <circle className="iris-rim" r="41.5" />
      <g clipPath="url(#iris-clip)">
        <g className="iris-turn">
          {Array.from({ length: blades }, (_, i) => (
            <g key={i} transform={`rotate(${(360 / blades) * i})`}>
              <path className="iris-blade" d="M0 -74 L74 -74 L74 -14 L0 16 Z" fill="url(#iris-blade)" />
            </g>
          ))}
        </g>
      </g>
      <g className="iris-glyph">
        <path d="M0 -13 V-2" />
        <path d="M-9.6 -9.2 A13 13 0 1 0 9.6 -9.2" />
      </g>
    </svg>
  );
}
