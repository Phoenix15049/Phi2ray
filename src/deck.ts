import { RefObject, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";

/** Where the server deck rests: 0 just a peek, 1 half way with the lens in reach, 2 full height. */
export type Snap = 0 | 1 | 2;

/** The half stop, as a share of the window height. */
const HALF = 0.45;
/** Share of the way to the next stop that a wheel gesture must cover to carry on to it. */
const COMMIT = 0.12;
/** How long a wheel gesture may pause before it counts as finished. */
const WHEEL_IDLE = 130;
/** A list scroll this recent keeps the wheel on the list, so a fling doesn't move the deck too. */
const LIST_HOLD = 260;
/** Spring, tuned to settle quickly with no bounce. */
const STIFFNESS = 400;
const DAMPING = 40;

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));

/**
 * Moves the deck with one spring, driven by clicks, drags and the wheel alike, and tells the stage
 * how far along it is through CSS variables (--t from peek to half, --u from half to full).
 */
export function useDeck(shell: RefObject<HTMLElement>) {
  const [snap, setSnap] = useState<Snap>(0);
  const list = useRef<HTMLDivElement>(null);
  const m = useRef({
    stops: [0, 0, 0],
    snap: 0 as Snap,
    y: 0,
    v: 0,
    target: 0,
    frame: 0,
    last: 0,
    gestureFrom: 0 as Snap,
    gestureLimit: 0,
    wheelTimer: 0,
    wheelAt: 0,
    listAt: 0,
    drag: null as null | { id: number; startY: number; fromY: number; moved: boolean; lastY: number; lastAt: number; speed: number },
  }).current;

  const paint = useCallback(() => {
    const el = shell.current;
    if (!el) return;
    const [peek, half, full] = m.stops;
    el.style.setProperty("--deck-y", `${m.y - full}px`);
    el.style.setProperty("--t", clamp((peek - m.y) / (peek - half), 0, 1).toFixed(4));
    el.style.setProperty("--u", clamp((half - m.y) / (half - full), 0, 1).toFixed(4));
  }, [shell, m]);

  const settled = useCallback(() => {
    // The deck hangs below the window at the half stop; the list's end must still be reachable.
    shell.current?.style.setProperty("--deck-rest", `${m.stops[m.snap] - m.stops[2]}px`);
  }, [shell, m]);

  const step = useCallback(
    (at: number) => {
      const dt = Math.min((at - m.last) / 1000, 0.032);
      m.last = at;
      m.v += (STIFFNESS * (m.target - m.y) - DAMPING * m.v) * dt;
      m.y += m.v * dt;
      if (Math.abs(m.target - m.y) < 0.4 && Math.abs(m.v) < 6) {
        m.y = m.target;
        m.v = 0;
        m.frame = 0;
        paint();
        settled();
        return;
      }
      paint();
      m.frame = requestAnimationFrame(step);
    },
    [m, paint, settled],
  );

  const run = useCallback(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      m.y = m.target;
      paint();
      settled();
      return;
    }
    if (m.frame) return;
    m.last = performance.now();
    m.frame = requestAnimationFrame(step);
  }, [m, paint, settled, step]);

  const go = useCallback(
    (next: Snap) => {
      m.snap = next;
      m.target = m.stops[next];
      setSnap(next);
      run();
    },
    [m, run],
  );

  // Stops depend on the window, and the stage needs to know how to fit above the half stop.
  useLayoutEffect(() => {
    const el = shell.current;
    if (!el) return;
    const measure = () => {
      const css = getComputedStyle(el);
      const px = (name: string) => parseFloat(css.getPropertyValue(name)) || 0;
      const height = el.clientHeight;
      m.stops = [height - px("--peek"), Math.round(height * HALF), px("--bar") + px("--mini")];
      m.y = m.target = m.stops[m.snap];
      m.v = 0;
      const stage = el.querySelector<HTMLElement>(".stage");
      const status = el.querySelector<HTMLElement>(".status");
      const field = el.querySelector<HTMLElement>(".field");
      if (stage && status && field) {
        const statusEnd = stage.offsetTop + status.offsetTop + status.offsetHeight * 0.86;
        const room = m.stops[1] - statusEnd;
        el.style.setProperty("--field-shift", `${(statusEnd + m.stops[1]) / 2 - (stage.offsetTop + field.offsetTop + field.offsetHeight / 2)}px`);
        el.style.setProperty("--field-scale", clamp((room - 4) / 132, 0.55, 1).toFixed(3));
      }
      paint();
      settled();
    };
    measure();
    const resize = new ResizeObserver(measure);
    resize.observe(el);
    const field = el.querySelector(".field");
    if (field) resize.observe(field);
    return () => resize.disconnect();
  }, [shell, m, paint, settled]);

  useEffect(() => () => cancelAnimationFrame(m.frame), [m]);

  /** Moves the deck with the wheel, one stop per gesture, then settles on a stop. */
  const wheel = useCallback(
    (delta: number) => {
      const now = Date.now();
      if (now - m.wheelAt > 220) {
        m.gestureFrom = m.snap;
        m.gestureLimit = m.stops[clamp(m.snap + Math.sign(delta), 0, 2)];
      }
      m.wheelAt = now;
      const from = m.stops[m.gestureFrom];
      const [lo, hi] = from < m.gestureLimit ? [from, m.gestureLimit] : [m.gestureLimit, from];
      m.target = clamp(m.target - delta * 0.8, lo, hi);
      run();
      clearTimeout(m.wheelTimer);
      m.wheelTimer = window.setTimeout(() => {
        const span = Math.abs(m.gestureLimit - from);
        const moved = span ? Math.abs(m.target - from) / span : 0;
        const next = clamp(m.gestureFrom + (m.gestureLimit < from ? 1 : -1), 0, 2) as Snap;
        go(moved > COMMIT ? next : m.gestureFrom);
      }, WHEEL_IDLE);
    },
    [m, run, go],
  );

  const onWheel = useCallback((e: React.WheelEvent) => wheel(e.deltaY), [wheel]);

  /** Over the list the wheel scrolls the list; the deck only moves once the list is at its end. */
  const onListWheel = useCallback(
    (e: React.WheelEvent) => {
      const el = list.current;
      if (!el) return;
      const atTop = el.scrollTop <= 0;
      const atEnd = el.scrollTop + el.clientHeight >= el.scrollHeight - 1;
      if ((e.deltaY > 0 ? atEnd : atTop) && Date.now() - m.listAt > LIST_HOLD) wheel(e.deltaY);
    },
    [m, wheel],
  );

  const onListScroll = useCallback(() => {
    m.listAt = Date.now();
  }, [m]);

  const dragProps = {
    onPointerDown: (e: React.PointerEvent<HTMLElement>) => {
      if ((e.target as Element).closest(".deck-actions, .deck-peek > .btn") || e.button !== 0) return;
      m.drag = { id: e.pointerId, startY: e.clientY, fromY: m.y, moved: false, lastY: e.clientY, lastAt: e.timeStamp, speed: 0 };
    },
    onPointerMove: (e: React.PointerEvent<HTMLElement>) => {
      const d = m.drag;
      if (!d || d.id !== e.pointerId) return;
      if (!d.moved) {
        if (Math.abs(e.clientY - d.startY) < 5) return;
        d.moved = true;
        e.currentTarget.setPointerCapture(e.pointerId);
        cancelAnimationFrame(m.frame);
        m.frame = 0;
        m.v = 0;
      }
      const elapsed = Math.max(e.timeStamp - d.lastAt, 1);
      d.speed = d.speed * 0.6 + ((e.clientY - d.lastY) / elapsed) * 1000 * 0.4;
      d.lastY = e.clientY;
      d.lastAt = e.timeStamp;
      m.y = m.target = clamp(d.fromY + e.clientY - d.startY, m.stops[2], m.stops[0]);
      paint();
    },
    onPointerUp: (e: React.PointerEvent<HTMLElement>) => {
      const d = m.drag;
      m.drag = null;
      if (!d?.moved) return;
      // Where a flick would carry the deck, then the stop closest to that.
      const landing = m.y + d.speed * 0.14;
      const nearest = m.stops.reduce((best, y, i) => (Math.abs(y - landing) < Math.abs(m.stops[best] - landing) ? i : best), 0);
      m.v = d.speed;
      go(nearest as Snap);
      e.stopPropagation();
    },
    onPointerCancel: () => {
      m.drag = null;
      go(m.snap);
    },
  };

  return { snap, go, list, onWheel, onListWheel, onListScroll, dragProps };
}
