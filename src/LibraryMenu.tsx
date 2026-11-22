import { ReactNode, useEffect, useLayoutEffect, useRef } from "react";
import { createPortal } from "react-dom";

export type MenuAction = {
  label: string;
  icon: ReactNode;
  run: () => void;
  disabled?: boolean;
  danger?: boolean;
};

export function LibraryMenu(props: {
  x: number;
  y: number;
  label: string;
  opener: HTMLElement;
  actions: MenuAction[];
  closing?: boolean;
  onClose: () => void;
  onExit: () => void;
}) {
  const menu = useRef<HTMLDivElement>(null);
  const close = useRef(props.onClose);
  close.current = props.onClose;
  const exit = useRef(props.onExit);
  exit.current = props.onExit;
  useEffect(() => {
    if (!props.closing) return;
    const timer = window.setTimeout(() => exit.current(), 180);
    return () => clearTimeout(timer);
  }, [props.closing]);

  const dismiss = () => {
    close.current();
    if (props.opener.isConnected) props.opener.focus({ preventScroll: true });
  };

  useLayoutEffect(() => {
    if (props.closing) return;
    const node = menu.current!;
    const gap = 8;
    const width = node.offsetWidth;
    const height = node.offsetHeight;
    const x = document.dir === "rtl" ? props.x - width : props.x;
    node.style.left = `${Math.max(gap, Math.min(x, window.innerWidth - width - gap))}px`;
    const top = Math.max(gap, Math.min(props.y, window.innerHeight - height - gap));
    node.style.top = `${top}px`;
    node.style.transformOrigin = `${Math.max(0, Math.min(width, props.x - node.offsetLeft))}px ${top < props.y ? "bottom" : "top"}`;
    node.querySelector<HTMLButtonElement>("button:not(:disabled)")?.focus({ preventScroll: true });
    const pointer = (event: PointerEvent) => {
      if (!node.contains(event.target as Node)) close.current();
    };
    const outsideScroll = (event: Event) => {
      if (!node.contains(event.target as Node)) close.current();
    };
    const resize = () => close.current();
    window.addEventListener("pointerdown", pointer, true);
    window.addEventListener("scroll", outsideScroll, true);
    window.addEventListener("resize", resize);
    window.addEventListener("blur", resize);
    return () => {
      window.removeEventListener("pointerdown", pointer, true);
      window.removeEventListener("scroll", outsideScroll, true);
      window.removeEventListener("resize", resize);
      window.removeEventListener("blur", resize);
    };
  }, [props.x, props.y, props.closing, props.opener]);

  return createPortal(
    <div className="library-menu" ref={menu} role={props.closing ? undefined : "menu"} aria-label={props.label}
      data-closing={props.closing || undefined} {...(props.closing ? { inert: "" } : {})}
      onAnimationEnd={() => { if (props.closing) exit.current(); }}
      onContextMenu={(event) => event.preventDefault()}
      onKeyDown={(event) => {
        if (event.key === "Escape" || event.key === "Tab") {
          if (event.key === "Escape") event.preventDefault();
          event.stopPropagation();
          dismiss();
          return;
        }
        if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return;
        event.preventDefault();
        const buttons = [...event.currentTarget.querySelectorAll<HTMLButtonElement>("button:not(:disabled)")];
        if (!buttons.length) return;
        const index = buttons.indexOf(document.activeElement as HTMLButtonElement);
        const next = event.key === "Home" ? 0 : event.key === "End" ? buttons.length - 1 :
          (index + (event.key === "ArrowDown" ? 1 : -1) + buttons.length) % buttons.length;
        buttons[next].focus();
      }}>
      <div className="library-menu-label" dir="auto">{props.label}</div>
      {props.actions.map((action) => (
        <button key={action.label} type="button" role="menuitem" className={action.danger ? "danger" : undefined}
          disabled={action.disabled} onClick={() => { dismiss(); action.run(); }}>
          {action.icon}<span>{action.label}</span>
        </button>
      ))}
    </div>,
    document.body,
  );
}
