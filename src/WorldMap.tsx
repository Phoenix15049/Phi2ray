import { useEffect, useMemo, useState } from "react";
import { LAND, MAP_HEIGHT, MAP_STEP, MAP_TOP } from "./mapData";

export type MapPoint = { kind: "you" | "entry" | "exit"; label: string; lat: number; lon: number };

const WIDTH = 360;
const HEIGHT = 150;
/** Closer than this, two points are drawn as one. */
const SAME_PLACE = 5;
const MAX_ZOOM = 3.4;

const project = (lat: number, lon: number) => ({ x: lon + 180, y: MAP_TOP - lat });

/**
 * A dotted world map that closes in on the points and draws the connection between them. The
 * lines join the places the connection is known to touch: the route between them isn't visible
 * from here, so they say which places, not which cables.
 */
export function WorldMap({ points }: { points: MapPoint[] }) {
  const [zoomed, setZoomed] = useState(false);
  useEffect(() => {
    const timer = setTimeout(() => setZoomed(true), 250);
    return () => clearTimeout(timer);
  }, []);

  const view = useMemo(() => {
    const projected = points.map((p) => project(p.lat, p.lon));
    if (!projected.length) return { k: 1, dx: 0, dy: (HEIGHT - MAP_HEIGHT) / 2 };
    const xs = projected.map((p) => p.x);
    const ys = projected.map((p) => p.y);
    const [minX, maxX, minY, maxY] = [Math.min(...xs), Math.max(...xs), Math.min(...ys), Math.max(...ys)];
    const k = Math.min(MAX_ZOOM, Math.max(1, Math.min(WIDTH / (maxX - minX + 70), HEIGHT / (maxY - minY + 50))));
    // Centred on the points, but never showing past the edge of the map.
    const clamp = (v: number, lo: number, hi: number) => Math.min(Math.max(v, Math.min(lo, hi)), Math.max(lo, hi));
    return {
      k,
      dx: clamp(WIDTH / 2 - ((minX + maxX) / 2) * k, 0, WIDTH - WIDTH * k),
      dy: clamp(HEIGHT / 2 - ((minY + maxY) / 2) * k, 0, HEIGHT - MAP_HEIGHT * k),
    };
  }, [points]);

  // Points in screen units, merged when they're the same place.
  const marks = useMemo(() => {
    const merged: { x: number; y: number; kinds: MapPoint["kind"][]; labels: string[] }[] = [];
    for (const p of points) {
      const { x, y } = project(p.lat, p.lon);
      const at = { x: x * view.k + view.dx, y: y * view.k + view.dy };
      const same = merged.find((m) => Math.hypot(m.x - at.x, m.y - at.y) < SAME_PLACE);
      if (same) {
        same.kinds.push(p.kind);
        if (!same.labels.includes(p.label)) same.labels.push(p.label);
      } else {
        merged.push({ ...at, kinds: [p.kind], labels: [p.label] });
      }
    }
    return merged;
  }, [points, view]);

  const arcs = useMemo(
    () =>
      marks.slice(1).map((to, i) => {
        const from = marks[i];
        const lift = Math.hypot(to.x - from.x, to.y - from.y) * 0.24;
        return `M${from.x} ${from.y}Q${(from.x + to.x) / 2} ${(from.y + to.y) / 2 - lift} ${to.x} ${to.y}`;
      }),
    [marks],
  );

  const scale = zoomed ? view.k : 1;
  const shift = zoomed ? `${view.dx}px, ${view.dy}px` : `0px, ${(HEIGHT - MAP_HEIGHT) / 2}px`;

  return (
    <svg className={`world ${zoomed ? "zoomed" : ""}`} viewBox={`0 0 ${WIDTH} ${HEIGHT}`} aria-hidden="true">
      <g className="world-land" style={{ transform: `translate(${shift}) scale(${scale})` }}>
        <path d={LAND} strokeDasharray={`0 ${MAP_STEP}`} strokeWidth={1.25 / Math.sqrt(scale)} />
      </g>
      {arcs.map((d, i) => (
        <g key={d} style={{ "--i": i } as React.CSSProperties}>
          <path className="world-arc" d={d} pathLength={100} />
          <path className="world-comet" d={d} pathLength={100} />
        </g>
      ))}
      {marks.map((m, i) => {
        const end = m.x > WIDTH - 60;
        return (
          <g key={i} className={`world-mark ${m.kinds[m.kinds.length - 1]}`} style={{ "--i": i, transform: `translate(${m.x}px, ${m.y}px)` } as React.CSSProperties}>
            <circle className="world-ring" r="4" />
            <circle className="world-dot" r="2.6" />
            <text x={end ? -7 : 7} y="3" textAnchor={end ? "end" : "start"}>
              {m.labels.join(" · ")}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
