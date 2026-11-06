import { useState } from "react";
import { DEFAULT_GROUP, Group } from "./api";
import { useT } from "./i18n";
import { Segmented, Sheet, Switch } from "./ui";

export type AddKind = "links" | "subscription" | "group";

/** True for a single http(s) link, which is a subscription rather than server links. */
export function looksLikeSubscription(text: string) {
  return /^https?:\/\/\S+$/i.test(text.trim());
}

export function AddSheet(props: {
  initialKind: AddKind;
  initialText: string;
  groups: Group[];
  defaultGroupId: string;
  onAddLinks: (text: string, groupId: string) => Promise<boolean>;
  onAddSubscription: (url: string) => Promise<boolean>;
  onCreateGroup: (name: string) => Promise<boolean>;
  onClose: () => void;
}) {
  const t = useT();
  const [kind, setKind] = useState<AddKind>(props.initialKind);
  const [links, setLinks] = useState(props.initialKind === "links" ? props.initialText : "");
  const [url, setUrl] = useState(props.initialKind === "subscription" ? props.initialText : "");
  const [name, setName] = useState("");
  const manualGroups = props.groups.filter((g) => !g.subscription);
  const [groupId, setGroupId] = useState(
    manualGroups.some((g) => g.id === props.defaultGroupId) ? props.defaultGroupId : DEFAULT_GROUP,
  );
  const [working, setWorking] = useState(false);

  const run = async (action: () => Promise<boolean>) => {
    setWorking(true);
    const done = await action();
    setWorking(false);
    if (done) props.onClose();
  };

  const submit = () => {
    if (kind === "links") {
      // A pasted subscription link goes where it belongs.
      if (looksLikeSubscription(links)) {
        setUrl(links.trim());
        setKind("subscription");
        return;
      }
      return run(() => props.onAddLinks(links, groupId));
    }
    if (kind === "subscription") return run(() => props.onAddSubscription(url));
    return run(() => props.onCreateGroup(name));
  };

  const canSubmit = !working && (kind === "links" ? links.trim() : kind === "subscription" ? url.trim() : name.trim());

  return (
    <Sheet dialog title={t("addTitle")} onClose={props.onClose}>
      <Segmented
        className="wide"
        label={t("addTitle")}
        value={kind}
        options={[
          { value: "links", label: t("links") },
          { value: "subscription", label: t("subscription") },
          { value: "group", label: t("newGroup") },
        ]}
        onChange={setKind}
      />

      {kind === "links" && (
        <>
          <textarea
            autoFocus
            className="import-box ltr-input"
            placeholder={t("linksPlaceholder")}
            value={links}
            onChange={(e) => setLinks(e.target.value)}
            spellCheck={false}
          />
          {manualGroups.length > 1 && (
            <label className="field-row">
              <span>{t("addTo")}</span>
              <select className="select" value={groupId} onChange={(e) => setGroupId(e.target.value)}>
                {manualGroups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              </select>
            </label>
          )}
          <p className="hint">{t("linksHint")}</p>
        </>
      )}

      {kind === "subscription" && (
        <>
          <input
            autoFocus
            className="input full ltr-input"
            placeholder="https://…"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && canSubmit && submit()}
            spellCheck={false}
          />
          <p className="hint">{t("subscriptionHint")}</p>
        </>
      )}

      {kind === "group" && (
        <>
          <input
            autoFocus
            className="input full"
            placeholder={t("groupNamePlaceholder")}
            maxLength={60}
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && canSubmit && submit()}
          />
          <p className="hint">{t("groupHint")}</p>
        </>
      )}

      <div className="sheet-actions">
        <button className="btn" onClick={props.onClose}>
          {t("cancel")}
        </button>
        <button className="btn primary" onClick={submit} disabled={!canSubmit}>
          {working ? (kind === "subscription" ? t("downloading") : t("adding")) : kind === "group" ? t("create") : t("add")}
        </button>
      </div>
    </Sheet>
  );
}

export function GroupSheet(props: {
  group: Group;
  count: number;
  onSave: (name: string, url?: string, autoUpdate?: boolean) => Promise<boolean>;
  onDelete: () => Promise<boolean>;
  onClose: () => void;
}) {
  const t = useT();
  const g = props.group;
  const sub = g.subscription;
  const [name, setName] = useState(g.name);
  const [url, setUrl] = useState(sub?.url ?? "");
  const [autoUpdate, setAutoUpdate] = useState(sub?.autoUpdate ?? true);
  const [confirming, setConfirming] = useState(false);
  const [working, setWorking] = useState(false);

  const run = async (action: () => Promise<boolean>) => {
    setWorking(true);
    const done = await action();
    setWorking(false);
    if (done) props.onClose();
  };

  return (
    <Sheet dialog title={sub ? t("subscription") : t("group")} onClose={props.onClose}>
      <label className="stack-field">
        <span>{t("name")}</span>
        <input className="input full" value={name} maxLength={60} onChange={(e) => setName(e.target.value)} />
      </label>
      {sub && (
        <>
          <label className="stack-field">
            <span>{t("link")}</span>
            <input className="input full ltr-input" value={url} onChange={(e) => setUrl(e.target.value)} spellCheck={false} />
          </label>
          <div className="group">
            <div className="row-setting">
              <div className="row-text">
                <strong>{t("updateAutomatically")}</strong>
                <span>{t("everyHours", { n: sub.intervalHours })}</span>
              </div>
              <Switch checked={autoUpdate} onChange={setAutoUpdate} label={t("updateAutomatically")} />
            </div>
          </div>
        </>
      )}

      <div className="sheet-actions spread">
        {g.id !== DEFAULT_GROUP &&
          (confirming ? (
            <button className="btn danger" onClick={() => run(props.onDelete)} disabled={working}>
              {t("confirmDelete", { n: props.count })}
            </button>
          ) : (
            <button className="btn ghost-danger" onClick={() => setConfirming(true)}>
              {sub ? t("deleteSubscription") : t("deleteGroup")}
            </button>
          ))}
        <span className="spacer" />
        <button className="btn" onClick={props.onClose}>
          {t("cancel")}
        </button>
        <button
          className="btn primary"
          disabled={working || !name.trim() || (!!sub && !url.trim())}
          onClick={() => run(() => props.onSave(name, sub ? url : undefined, sub ? autoUpdate : undefined))}
        >
          {t("save")}
        </button>
      </div>
    </Sheet>
  );
}
