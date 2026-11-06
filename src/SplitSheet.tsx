import { useEffect, useMemo, useState } from "react";
import { api, Mode, RunningApp, SplitTunnel } from "./api";
import { useT } from "./i18n";
import { Icon, Segmented, Sheet, Switch } from "./ui";

/** Splits pasted text like "a.com, b.com\nc.com" into entries. */
const entries = (text: string) =>
  text
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);

const fileName = (app: string) => app.split(/[\\/]/).pop() ?? app;

export function SplitSheet(props: {
  value: SplitTunnel;
  connectionMode: Mode;
  onChange: (split: SplitTunnel) => Promise<boolean>;
  onBack: () => void;
}) {
  const t = useT();
  const s = props.value;
  const [siteDraft, setSiteDraft] = useState("");
  const [appDraft, setAppDraft] = useState("");
  const [picking, setPicking] = useState(false);

  const update = (patch: Partial<SplitTunnel>) => props.onChange({ ...s, ...patch });

  const addSites = async () => {
    const added = entries(siteDraft);
    if (added.length && (await update({ sites: [...s.sites, ...added] }))) setSiteDraft("");
  };

  const addApp = async (app: string) => {
    if (await update({ apps: [...s.apps, app] })) setAppDraft("");
  };

  const appsNeedVpn = s.enabled && s.apps.length > 0 && props.connectionMode !== "tun";

  return (
    <Sheet title={t("splitTunnel")} onClose={props.onBack}>
      <div className="group">
        <div className="row-setting">
          <div className="row-text">
            <strong>{t("splitEnable")}</strong>
            <span>{t("splitEnableHint")}</span>
          </div>
          <Switch checked={s.enabled} onChange={(enabled) => update({ enabled })} label={t("splitEnable")} />
        </div>
      </div>

      <div className={`split-body ${s.enabled ? "" : "disabled"}`}>
        <Segmented
          className="wide split-mode"
          label={t("splitTunnel")}
          value={s.mode}
          options={[
            { value: "exclude", label: t("splitExclude") },
            { value: "include", label: t("splitInclude") },
          ]}
          onChange={(mode) => update({ mode })}
        />
        <p className="split-explain">{s.mode === "exclude" ? t("splitExcludeHint") : t("splitIncludeHint")}</p>

        <section className="settings-section">
          <h3>
            {t("splitApps")} <span className="count-pill">{s.apps.length}</span>
          </h3>
          {appsNeedVpn && <div className="alert warn compact">{t("splitAppsNeedVpn")}</div>}
          {s.apps.length > 0 && (
            <ul className="entry-list">
              {s.apps.map((app) => (
                <li key={app}>
                  <span className="entry-icon">{fileName(app).charAt(0).toUpperCase()}</span>
                  <span className="entry-text">
                    <strong className="ltr">{fileName(app)}</strong>
                    {app.includes("\\") && <span className="ltr">{app}</span>}
                  </span>
                  <button
                    className="icon-btn danger"
                    onClick={() => update({ apps: s.apps.filter((a) => a !== app) })}
                    aria-label={`${t("deleteServer")} ${app}`}
                  >
                    {Icon.close()}
                  </button>
                </li>
              ))}
            </ul>
          )}
          <div className="entry-add">
            <input
              className="input ltr-input"
              value={appDraft}
              placeholder="Telegram.exe"
              spellCheck={false}
              onChange={(e) => setAppDraft(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && appDraft.trim() && addApp(appDraft.trim())}
            />
            <button className="btn" onClick={() => addApp(appDraft.trim())} disabled={!appDraft.trim()}>
              {Icon.plus()}
              {t("add")}
            </button>
            <button className={`btn ${picking ? "primary" : ""}`} onClick={() => setPicking((p) => !p)}>
              {t("splitRunningApps")}
            </button>
          </div>
          {picking && <AppPicker taken={s.apps} onPick={(app) => addApp(app)} />}
        </section>

        <section className="settings-section">
          <h3>
            {t("splitSites")} <span className="count-pill">{s.sites.length}</span>
          </h3>
          <p className="section-hint">{t("splitSitesHint")}</p>
          {s.sites.length > 0 && (
            <div className="chips">
              {s.sites.map((site) => (
                <span key={site} className="entry-chip">
                  <span className="ltr">{site}</span>
                  <button onClick={() => update({ sites: s.sites.filter((x) => x !== site) })} aria-label={`${t("deleteServer")} ${site}`}>
                    {Icon.close()}
                  </button>
                </span>
              ))}
            </div>
          )}
          <div className="entry-add">
            <input
              className="input ltr-input"
              value={siteDraft}
              placeholder="example.com, 1.2.3.4, 10.0.0.0/8"
              spellCheck={false}
              onChange={(e) => setSiteDraft(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && addSites()}
            />
            <button className="btn" onClick={addSites} disabled={!siteDraft.trim()}>
              {Icon.plus()}
              {t("add")}
            </button>
          </div>
        </section>

        <p className="hint">{t("splitReconnectHint")}</p>
      </div>
    </Sheet>
  );
}

/** Running programs to pick from, with search. */
function AppPicker(props: { taken: string[]; onPick: (app: string) => void }) {
  const t = useT();
  const [apps, setApps] = useState<RunningApp[] | null>(null);
  const [query, setQuery] = useState("");

  useEffect(() => {
    api.runningApps().then(setApps).catch(() => setApps([]));
  }, []);

  const taken = useMemo(() => new Set(props.taken.map((a) => fileName(a).toLowerCase())), [props.taken]);
  // One row per program name: picking by name keeps working after the app updates and moves.
  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    const seen = new Set<string>();
    return (apps ?? []).filter((a) => {
      const key = a.name.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return !q || key.includes(q) || a.path.toLowerCase().includes(q);
    });
  }, [apps, query]);

  return (
    <div className="picker">
      <label className="search">
        {Icon.search()}
        <input autoFocus value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("splitSearchApps")} />
      </label>
      <ul className="picker-list">
        {apps === null && <li className="picker-empty">{t("checking")}</li>}
        {apps !== null && visible.length === 0 && <li className="picker-empty">{t("splitNoApps")}</li>}
        {visible.map((a) => {
          const added = taken.has(a.name.toLowerCase());
          return (
            <li key={a.path}>
              <button onClick={() => props.onPick(a.name)} disabled={added} title={a.path}>
                <span className="entry-icon">{a.name.charAt(0).toUpperCase()}</span>
                <span className="entry-text">
                  <strong className="ltr">{a.name}</strong>
                  <span className="ltr">{a.path}</span>
                </span>
                {added ? <span className="picker-added">{Icon.check()}</span> : <span className="picker-add">{Icon.plus()}</span>}
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
