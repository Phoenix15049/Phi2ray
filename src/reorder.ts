import { RefObject, useEffect, useLayoutEffect, useRef, useState } from "react";

type Item = { id: string; starred?: boolean };
type Drag = {
  id: string;
  pointer: number;
  capture: HTMLElement;
  order: string[];
  start: number;
  point: number;
  grab: number;
  frame: number;
  moved: boolean;
};

const reducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

export function useReorder<T extends Item>(
  items: T[], root: RefObject<HTMLElement>, viewport: RefObject<HTMLElement>,
  axis: "x" | "y", disabled: boolean, commit: (id: string, target: string) => Promise<unknown>,
) {
  const [preview, setPreview] = useState<string[] | null>(null);
  const [dragging, setDragging] = useState<string | null>(null);
  const drag = useRef<Drag | null>(null);
  const saving = useRef(false);
  const nodes = useRef(new Map<string, HTMLElement>());
  const rendered = useRef<string[]>([]);
  const positions = useRef(new Map<string, number>());
  const animations = useRef(new Map<HTMLElement, Animation>());
  const byId = new Map(items.map((item) => [item.id, item]));
  const original = items.map((item) => item.id);
  const signature = JSON.stringify(original.map((id) => [id, byId.get(id)?.starred]));
  const visible = preview && !disabled && preview.length === items.length && preview.every((id) => byId.has(id))
    ? preview.map((id) => byId.get(id)!)
    : items;
  const horizontal = axis === "x";
  const layout = (node: HTMLElement) => horizontal ? node.offsetLeft : node.offsetTop;
  const size = (node: HTMLElement) => horizontal ? node.offsetWidth : node.offsetHeight;
  const scroll = (node: HTMLElement) => horizontal ? node.scrollLeft : node.scrollTop;
  const start = (rect: DOMRect) => horizontal ? rect.left : rect.top;
  const direction = () => horizontal && document.dir === "rtl" ? -1 : 1;
  const sameSection = (a: string, b: string) => byId.get(a)?.starred === byId.get(b)?.starred;

  const follow = (d: Drag, node: HTMLElement) => {
    const list = root.current!;
    const origin = start(list.getBoundingClientRect()) - scroll(list);
    const shift = d.point - d.grab - origin - layout(node);
    node.style.translate = horizontal ? `${shift}px 0px` : `0px ${shift}px`;
  };

  useLayoutEffect(() => {
    const nextNodes = new Map<string, HTMLElement>();
    const nextPositions = new Map<string, number>();
    for (const child of Array.from(root.current?.children ?? [])) {
      if (!(child instanceof HTMLElement) || !child.dataset.sortId) continue;
      const id = child.dataset.sortId;
      const next = layout(child);
      nextNodes.set(id, child);
      nextPositions.set(id, next);
      if (dragging === id && drag.current?.moved) {
        animations.current.get(child)?.cancel();
        follow(drag.current, child);
        continue;
      }
      const before = positions.current.get(id);
      const lifted = parseFloat(child.style.translate.split(" ")[horizontal ? 0 : 1]) || 0;
      child.style.translate = "";
      if (before === undefined || nodes.current.get(id) !== child || (before === next && !lifted) || reducedMotion()) continue;
      const animation = animations.current.get(child);
      const transform = animation ? getComputedStyle(child).transform : "none";
      const matrix = new DOMMatrixReadOnly(transform === "none" ? undefined : transform);
      const delta = before - next + lifted + (horizontal ? matrix.m41 : matrix.m42);
      animation?.cancel();
      const move = child.animate([{ transform: `translate${horizontal ? "X" : "Y"}(${delta}px)` },
        { transform: "none" }], { duration: 245, easing: "cubic-bezier(.22,.75,.25,1)" });
      animations.current.set(child, move);
      move.onfinish = () => { if (animations.current.get(child) === move) animations.current.delete(child); };
    }
    for (const [node, animation] of animations.current) {
      if (!node.isConnected) { animation.cancel(); animations.current.delete(node); }
    }
    nodes.current = nextNodes;
    positions.current = nextPositions;
    rendered.current = [...nextNodes.keys()];
  });

  const finish = (drop: boolean) => {
    const d = drag.current;
    if (!d) return;
    drag.current = null;
    cancelAnimationFrame(d.frame);
    if (d.capture.hasPointerCapture(d.pointer)) d.capture.releasePointerCapture(d.pointer);
    setDragging(null);
    const at = d.order.indexOf(d.id);
    const target = original[at];
    if (!drop || !d.moved || !target || target === d.id) {
      setPreview(null);
      return;
    }
    saving.current = true;
    void commit(d.id, target).finally(() => {
      saving.current = false;
      setPreview(null);
    });
  };

  const cancel = useRef(() => finish(false));
  cancel.current = () => finish(false);
  useLayoutEffect(() => { if (drag.current) cancel.current(); }, [signature, disabled]);
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || !drag.current) return;
      e.preventDefault();
      e.stopPropagation();
      cancel.current();
    };
    const blur = () => cancel.current();
    window.addEventListener("keydown", key, true);
    window.addEventListener("blur", blur);
    return () => {
      window.removeEventListener("keydown", key, true);
      window.removeEventListener("blur", blur);
      if (drag.current) cancelAnimationFrame(drag.current.frame);
    };
  }, []);

  function tick(d: Drag) {
    if (drag.current !== d || !root.current || !viewport.current) return;
    const view = viewport.current;
    const node = nodes.current.get(d.id);
    if (!node) return;
    const bounds = view.getBoundingClientRect();
    const min = start(bounds);
    const max = Math.min(min + (horizontal ? view.clientWidth : view.clientHeight),
      horizontal ? window.innerWidth : window.innerHeight);
    const distance = Math.min(d.point - min, max - d.point);
    if (distance < 32) {
      const step = Math.min(14, 1 + (32 - distance) / 3) * (d.point < (min + max) / 2 ? -1 : 1);
      if (horizontal) view.scrollLeft += step;
      else view.scrollTop += step;
    }
    follow(d, node);
    if (d.order.indexOf(d.id) === rendered.current.indexOf(d.id)) {
      const list = root.current;
      const point = d.point - start(list.getBoundingClientRect()) + scroll(list);
      const from = d.order.indexOf(d.id);
      let to = from;
      for (const step of [-1, 1]) {
        for (let index = from + step; index >= 0 && index < d.order.length; index += step) {
          if (!sameSection(d.id, d.order[index])) break;
          const peer = nodes.current.get(d.order[index])!;
          if ((point - layout(peer) - size(peer) / 2) * step * direction() < 0) break;
          to = index;
        }
      }
      if (to !== from) {
        const next = [...d.order];
        next.splice(to, 0, next.splice(from, 1)[0]);
        d.order = next;
        setPreview(next);
      }
    }
    d.frame = requestAnimationFrame(() => tick(d));
  }

  const handle = (id: string) => ({
    disabled: disabled || !items.some((item) => item.id !== id && sameSection(id, item.id)),
    onPointerDown: (event: React.PointerEvent<HTMLButtonElement>) => {
      if (event.button !== 0 || !event.isPrimary || drag.current || saving.current) return;
      const item = nodes.current.get(id);
      const capture = root.current;
      if (!item || !capture) return;
      const point = horizontal ? event.clientX : event.clientY;
      capture.setPointerCapture(event.pointerId);
      drag.current = {
        id, pointer: event.pointerId, capture, order: original, start: point, point,
        grab: point - start(item.getBoundingClientRect()), frame: 0, moved: false,
      };
    },
    onKeyDown: (event: React.KeyboardEvent<HTMLButtonElement>) => {
      const keys = horizontal ? ["ArrowLeft", "ArrowRight"] : ["ArrowUp", "ArrowDown"];
      const step = keys.indexOf(event.key);
      if (step < 0 || saving.current || drag.current) return;
      event.preventDefault();
      const peers = original.filter((peer) => sameSection(id, peer));
      const target = peers[peers.indexOf(id) + (step === 0 ? -1 : 1) * direction()];
      if (!target) return;
      saving.current = true;
      const control = event.currentTarget;
      void commit(id, target).finally(() => {
        saving.current = false;
        requestAnimationFrame(() => { if (document.activeElement === document.body) control.focus({ preventScroll: true }); });
      });
    },
  });

  const pointer = {
    onPointerMove: (event: React.PointerEvent<HTMLElement>) => {
      const d = drag.current;
      if (!d || d.pointer !== event.pointerId) return;
      d.point = horizontal ? event.clientX : event.clientY;
      if (!d.moved && Math.abs(d.point - d.start) >= 5) {
        d.moved = true;
        setDragging(d.id);
        d.frame = requestAnimationFrame(() => tick(d));
      }
    },
    onPointerUp: (event: React.PointerEvent<HTMLElement>) => {
      const d = drag.current;
      if (d?.pointer !== event.pointerId) return;
      if (d.moved) {
        d.point = horizontal ? event.clientX : event.clientY;
        cancelAnimationFrame(d.frame);
        tick(d);
      }
      finish(true);
    },
    onLostPointerCapture: (event: React.PointerEvent<HTMLElement>) => {
      if (drag.current?.pointer === event.pointerId) finish(false);
    },
  };
  return { visible, dragging, handle, pointer };
}
