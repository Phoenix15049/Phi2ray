import { useCallback, useEffect, useState } from "react";
import { api, ConnectionInfo, Geo } from "./api";
import { useT } from "./i18n";
import { countryName, Icon, Sheet } from "./ui";

/** Providers whose IPs mean the connection enters through a CDN rather than a plain relay. */
const CDN = /cloudflare|fastly|akamai|arvan|gcore|g-core|cdn77|bunny|cloudfront|edgecast|stackpath|imperva|incapsula/i;

/** The value most answers agree on, and how many agree out of how many answered. */
function consensus(values: (string | null | undefined)[]) {
  const given = values.filter((v): v is string => !!v);
  const counts = new Map<string, number>();
  for (const v of given) counts.set(v, (counts.get(v) ?? 0) + 1);
  let best: string | null = null;
  let agree = 0;
  for (const [v, n] of counts) {
    if (n > agree) [best, agree] = [v, n];
  }
  return { value: best, agree, total: given.length };
}

/** City and region from the first answer for `country` that has them. */
function place(geo: Geo[], country: string | null) {
  const g = geo.find((x) => x.country === country && x.city) ?? geo.find((x) => x.country === country);
  return [g?.city, g?.region && g.region !== g.city ? g.region : null].filter(Boolean).join(", ");
}

const pick = (geo: Geo[], key: "asn" | "org") => geo.find((g) => g[key])?.[key] ?? null;

type Route = "direct" | "sameNetwork" | "cdn" | "relay" | "private" | "unknown";

export function InfoSheet(props: { connected: boolean; language: string; onClose: () => void; onCopy: (text: string) => void }) {
  const t = useT();
  const [info, setInfo] = useState<ConnectionInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Looked up only when opened or refreshed: it asks outside services, so never in the background.
  const load = useCallback(() => {
    if (!props.connected) return;
    setLoading(true);
    setError(null);
    api
      .connectionInfo()
      .then(setInfo)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, [props.connected]);
  useEffect(load, [load]);

  const country = (code: string | null) => (code ? countryName(code, props.language) : t("unknown"));

  const body = () => {
    if (!props.connected) return <p className="lead">{t("infoNotConnected")}</p>;
    if (!info) {
      return error ? <div className="alert danger">{error}</div> : <p className="lead info-loading">{t("infoLooking")}</p>;
    }

    const answered = info.exit.filter((g) => g.ip);
    const ip = consensus([...answered.map((g) => g.ip), info.trace?.ip]);
    const geo = answered.filter((g) => g.ip === ip.value);
    const where = consensus(geo.map((g) => g.country));
    const exitAsn = pick(geo, "asn");
    const exitOrg = pick(geo, "org");
    const proxyFlag = geo.find((g) => g.proxy !== null)?.proxy ?? null;

    const entry = info.entry;
    const entryGeo = entry?.geo.filter((g) => g.ip) ?? [];
    const entryCountry = consensus(entryGeo.map((g) => g.country)).value;
    const entryAsn = pick(entryGeo, "asn");
    const entryOrg = pick(entryGeo, "org");

    let route: Route = "unknown";
    if (entry && !entry.public) route = "private";
    else if (entry && ip.value) {
      if (entry.ip === ip.value) route = "direct";
      else if (entryAsn && exitAsn && entryAsn === exitAsn) route = "sameNetwork";
      else route = entryOrg && CDN.test(entryOrg) ? "cdn" : "relay";
    }
    const hops = route === "cdn" || route === "relay";

    return (
      <>
        <div className="info-hero">
          <div className="info-hero-top">
            <strong className="info-country">{country(where.value)}</strong>
            {where.value && <span className="info-code ltr">{where.value}</span>}
          </div>
          <div className="info-ip-row">
            <span className="info-ip ltr selectable">{ip.value ?? "—"}</span>
            {ip.value && (
              <button className="btn small" onClick={() => props.onCopy(ip.value!)}>
                {t("copy")}
              </button>
            )}
          </div>
          <div className="info-meta">
            {place(geo, where.value) && <span>{place(geo, where.value)}</span>}
            {(exitAsn || exitOrg) && <span className="ltr">{[exitAsn, exitOrg].filter(Boolean).join(" · ")}</span>}
            {proxyFlag !== null && (
              <span>
                {t("infoProxyFlag")}: {proxyFlag ? t("yes") : t("no")}
              </span>
            )}
          </div>
          <div className="info-meta">
            <span>
              {t("infoAgreement")}: <span className="ltr">IP {ip.agree}/{ip.total}</span>
            </span>
            <span>
              {t("infoLocation")} <span className="ltr">{where.agree}/{where.total}</span>
            </span>
          </div>
        </div>

        <h3>{t("infoRoute")}</h3>
        <div className={`route-card ${hops ? "hops" : route}`}>
          <div className="route-path">
            <div className="route-node">
              <span className="route-label">{t("infoYou")}</span>
            </div>
            <span className="route-arrow" aria-hidden="true">
              {Icon.chevron()}
            </span>
            <div className="route-node">
              <span className="route-label">{t("infoEntry")}</span>
              <span className="route-value">{entry ? (entry.public ? country(entryCountry) : t("infoPrivate")) : "—"}</span>
            </div>
            {hops && (
              <>
                <span className="route-arrow dashed" aria-hidden="true">
                  {Icon.chevron()}
                </span>
                <div className="route-node">
                  <span className="route-label">{t("infoExit")}</span>
                  <span className="route-value">{country(where.value)}</span>
                </div>
              </>
            )}
            <span className="route-arrow" aria-hidden="true">
              {Icon.chevron()}
            </span>
            <div className="route-node">
              <span className="route-label">{t("infoInternet")}</span>
            </div>
          </div>
          <p className="route-verdict">{t(`route_${route}`)}</p>
        </div>

        <dl className="facts info-facts">
          {entry && (
            <>
              <dt>{t("infoServerAddress")}</dt>
              <dd className="ltr selectable">{entry.address}</dd>
              <dt>{t("infoEntryIp")}</dt>
              <dd className="ltr selectable">{entry.ip}</dd>
              {(entryAsn || entryOrg) && (
                <>
                  <dt>{t("infoEntryNetwork")}</dt>
                  <dd className="ltr">{[entryAsn, entryOrg].filter(Boolean).join(" · ")}</dd>
                </>
              )}
            </>
          )}
          <dt>{t("infoExitIp")}</dt>
          <dd className="ltr selectable">{ip.value ?? "—"}</dd>
          {info.trace && (
            <>
              <dt>Cloudflare</dt>
              <dd className="ltr">{[info.trace.ip, info.trace.country, info.trace.colo && `colo ${info.trace.colo}`].filter(Boolean).join(" · ")}</dd>
            </>
          )}
        </dl>

        <h3>{t("infoDatabases")}</h3>
        <dl className="facts info-facts">
          {info.exit.map((g) => (
            <GeoRow key={g.source} geo={g} />
          ))}
        </dl>
        <p className="hint">{t("infoHint")}</p>
      </>
    );
  };

  return (
    <Sheet
      title={t("connectionInfo")}
      onClose={props.onClose}
      actions={
        props.connected && (
          <div className="sheet-head-actions">
            <button className={`icon-btn ${loading ? "spinning" : ""}`} onClick={load} disabled={loading} aria-label={t("checkAgain")} title={t("checkAgain")}>
              {Icon.refresh()}
            </button>
          </div>
        )
      }
    >
      {body()}
    </Sheet>
  );
}

function GeoRow({ geo }: { geo: Geo }) {
  return (
    <>
      <dt>{geo.source}</dt>
      {geo.error ? (
        <dd className="muted">{geo.error}</dd>
      ) : (
        <dd className="ltr">{[geo.country, geo.city].filter(Boolean).join(" · ") || "—"}</dd>
      )}
    </>
  );
}
