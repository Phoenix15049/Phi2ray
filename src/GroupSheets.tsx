import { useRef, useState } from "react";
import { DEFAULT_GROUP, Group } from "./api";
import { importFileError, readImportFiles } from "./dropImport";
import { useT } from "./i18n";
import { Icon, Segmented, Sheet, Switch } from "./ui";

export type AddKind = "links" | "subscription" | "group";

export function LibraryDialog(props: {
  action: "rename" | "delete" | "export";
  name: string;
  count?: number;
  opener: HTMLElement;
  onConfirm: (name: string) => Promise<boolean>;
  onClose: () => void;
}) {
  const t = useT();
  const [name, setName] = useState(props.name);
  const [working, setWorking] = useState(false);
  const rename = props.action === "rename";
  const deleting = props.action === "delete";
  const label = t(rename ? "renameItem" : deleting ? "deleteServer" : "exportConfigs");
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (working || (rename && !name.trim())) return;
    setWorking(true);
    try {
      if (await props.onConfirm(name.trim())) props.onClose();
    } finally {
      setWorking(false);
    }
  };
  return (
    <Sheet dialog title={deleting && props.count !== undefined ? t("deleteGroup") : label} returnFocusTo={props.opener}
      onClose={() => { if (!working) props.onClose(); }}>
      <form onSubmit={submit}>
        {rename ? (
          <label className="stack-field">
            <span>{t("name")}</span>
            <input autoFocus className="input full" maxLength={60} value={name} onChange={(event) => setName(event.target.value)} />
          </label>
        ) : (
          <>
            <p className="library-dialog-name" dir="auto">{props.name}</p>
            <p className="hint">{t(deleting ? props.count === undefined ? "deleteProfileText" : "deleteGroupText" : "exportCredentials", { n: props.count ?? 0 })}</p>
          </>
        )}
        <div className="sheet-actions">
          <button type="button" className="btn" disabled={working} onClick={props.onClose}>{t("cancel")}</button>
          <button type="submit" className={deleting ? "btn danger" : "btn primary"} disabled={working || (rename && !name.trim())}>
            {t(rename ? "save" : deleting ? "deleteServer" : "copy")}
          </button>
        </div>
      </form>
    </Sheet>
  );
}

/** True for a single http(s) link, which is a subscription rather than server links. */
export function looksLikeSubscription(text: string) {
  return /^https?:\/\/\S+$/i.test(text.trim());
}

export function AddSheet(props: {
  initialKind: AddKind;
  initialText: string;
  groups: Group[];
  defaultGroupId: string;
  onAddLinks: (text: string, groupId: string, newGroupName?: string) => Promise<boolean>;
  dropped?: boolean;
  onAddSubscription: (url: string) => Promise<boolean>;
  onCreateGroup: (name: string) => Promise<boolean>;
  onClose: () => void;
}) {
  const t = useT();
  const [kind, setKind] = useState<AddKind>(props.initialKind);
  const [links, setLinks] = useState(props.initialKind === "links" ? props.initialText : "");
  const [url, setUrl] = useState(props.initialKind === "subscription" ? props.initialText : "");
  const [name, setName] = useState("");
  const [groupId, setGroupId] = useState(
    props.groups.some((g) => g.id === props.defaultGroupId) ? props.defaultGroupId : DEFAULT_GROUP,
  );
  const [newGroupName, setNewGroupName] = useState("");
  const [working, setWorking] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const [fileError, setFileError] = useState<string | null>(null);

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
      return run(() => props.onAddLinks(links, groupId, groupId ? undefined : newGroupName));
    }
    if (kind === "subscription") return run(() => props.onAddSubscription(url));
    return run(() => props.onCreateGroup(name));
  };

  const canSubmit = !working && (kind === "links" ? links.trim() && (groupId || newGroupName.trim()) : kind === "subscription" ? url.trim() : name.trim());

  return (
    <Sheet dialog title={t(props.dropped ? "dropImportTitle" : "addTitle")} onClose={props.onClose}>
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
          <button type="button" className="btn small import-file-button" disabled={working} onClick={() => fileInput.current?.click()}>
            {Icon.down()}{t("chooseConfigFile")}
          </button>
          <input type="file" hidden ref={fileInput} onChange={async (event) => {
            const files = Array.from(event.target.files ?? []);
            event.target.value = "";
            if (!files.length) return;
            setFileError(null);
            setWorking(true);
            try {
              const text = await readImportFiles(files);
              if (text) setLinks(text);
              else setFileError(t("dropEmpty"));
            } catch (error) {
              setFileError(t(importFileError(error)));
            } finally {
              setWorking(false);
            }
          }} />
          {fileError && <p role="alert" className="hint">{fileError}</p>}
          <label className="field-row import-destination">
            <span>{t("addTo")}</span>
            <select className="select" value={groupId} onChange={(e) => setGroupId(e.target.value)}>
              {props.groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.id === DEFAULT_GROUP && g.name === "My servers" ? t("myServers") : g.name}
                  {g.id === props.defaultGroupId ? ` · ${t("currentGroup")}` : ""}
                </option>
              ))}
              <option value="">{t("newGroup")}</option>
            </select>
          </label>
          {!groupId && <label className="stack-field">
            <span>{t("groupNamePlaceholder")}</span>
            <input className="input full" maxLength={60} value={newGroupName} onChange={(e) => setNewGroupName(e.target.value)} />
          </label>}
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
