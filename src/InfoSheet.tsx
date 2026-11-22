import { useCallback, useEffect, useState } from "react";
import { api, ConnectionInfo, Geo, Quality } from "./api";
import { StringKey, useT } from "./i18n";
import { COUNTRIES, ZONES } from "./mapData";
import { countryName, Icon, Sheet } from "./ui";
import { MapPoint, WorldMap } from "./WorldMap";

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

/** A place for the map: the database's own coordinates, or else the country's. */
function coordinates(geo: Geo[], country: string | null): [number, number] | null {
  const exact = geo.find((g) => g.latitude !== null && g.longitude !== null && (!country || g.country === country));
  if (exact) return [exact.latitude!, exact.longitude!];
  return country ? (COUNTRIES[country] ?? null) : null;
}

/** A rough idea of where this PC is, from the time zone alone: nothing is looked up or sent. */
function ownPlace(): [number, number] | null {
  try {
    return ZONES[Intl.DateTimeFormat().resolvedOptions().timeZone] ?? null;
  } catch {
    return null;
  }
}

const pick = (geo: Geo[], key: "asn" | "org") => geo.find((g) => g[key])?.[key] ?? null;

type Route = "direct" | "sameNetwork" | "cdn" | "relay" | "private" | "unknown";

export function InfoSheet(props: { connected: boolean; absolute: boolean; language: string; onClose: () => void; onCopy: (text: string) => void }) {
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
    const reports = [...answered.map((g) => g.ip), ...(info.trace ? [info.trace.ip] : [])];
    const ip = { value: info.exitIp, agree: reports.filter((ip) => ip === info.exitIp).length, total: reports.length };
    const geo = answered.filter((g) => g.ip === ip.value);
    const where = consensus([...geo.map((g) => g.country), info.trace?.ip === ip.value ? info.trace.country : null]);
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

    const mark = (kind: MapPoint["kind"], label: string, at: [number, number] | null): MapPoint[] =>
      at ? [{ kind, label, lat: at[0], lon: at[1] }] : [];
    const points = [
      ...(!props.absolute ? mark("you", t("infoYou"), ownPlace()) : []),
      ...(entry?.public ? mark("entry", country(entryCountry), coordinates(entryGeo, entryCountry)) : []),
      ...mark("exit", country(where.value), coordinates(geo, where.value)),
    ];

    return (
      <>
        {error && <div className="alert warn" role="status">{error}</div>}
        <div className="info-hero">
          <div className="info-hero-top">
            <strong className="info-country">{country(where.value)}</strong>
            {where.value && <span className="info-code ltr">{where.value}</span>}
          </div>
          <div className="info-ip-row">
            <span className="info-ip ltr selectable">{ip.value ?? "—"}</span>
            <button className="btn small" onClick={() => props.onCopy(ip.value)}>{t("copy")}</button>
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
          {points.length > 0 && <WorldMap points={points} />}
          <ol className="route-steps">
            <li>
              <span className="route-label">{t("infoYou")}</span>
            </li>
            <li>
              <span className="route-label">{t("infoEntry")}</span>
              <span className="route-value">{entry ? (entry.public ? country(entryCountry) : t("infoPrivate")) : "—"}</span>
            </li>
            {hops && (
              <li className="relay">
                <span className="route-label">{t("infoExit")}</span>
                <span className="route-value">{country(where.value)}</span>
              </li>
            )}
            <li>
              <span className="route-label">{t("infoInternet")}</span>
            </li>
          </ol>
          <p className="route-verdict">{t(`route_${route}`)}</p>
          {points.length > 0 && !props.absolute && <p className="hint">{t("infoMapHint")}</p>}
        </div>

        {info.quality && <QualityCard quality={info.quality} />}

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
            <GeoRow key={g.source} geo={g} exitIp={info.exitIp} />
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
          <div className="head-actions">
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

const FLAGS: ["vpn" | "hosting" | "proxy" | "tor" | "compromised" | "scraper", StringKey][] = [
  ["vpn", "qualityVpnFlag"],
  ["proxy", "qualityProxyFlag"],
  ["tor", "qualityTorFlag"],
  ["hosting", "qualityHostingFlag"],
  ["compromised", "qualityCompromisedFlag"],
  ["scraper", "qualityScraperFlag"],
];

function QualityCard({ quality: q }: { quality: Quality }) {
  const t = useT();
  const answered = q.blocklists.filter((b) => b.listed !== null);
  const listed = q.blocklists.filter((b) => b.listed).length;
  const flagged = q.compromised === true || (q.attackCount ?? 0) > 0 || listed > 0;
  const threat = flagged ? "qualityReports" : q.compromised === false && q.attackCount === 0 ? "qualityNoReports" : "qualityUnknown";
  const riskTone = q.risk === null ? "" : q.risk >= 75 ? "bad" : q.risk >= 40 ? "warn" : "ok";
  const metrics: [StringKey, number | null, string][] = [
    ["qualityReputation", q.score, riskTone],
    ["qualityRisk", q.risk, riskTone],
    ["qualityConfidence", q.confidence, ""],
  ];
  return (
    <>
      <h3>{t("infoQuality")}</h3>
      <div className="quality">
        <div className="quality-metrics">
          {metrics.map(([label, score, tone]) => (
            <div className="quality-metric" data-tone={tone} key={label}>
              <span>{t(label)}</span>
              <strong className="ltr">{score === null ? "—" : <>{score}<small> / 100</small></>}</strong>
              {score !== null && <progress value={score} max={100} aria-label={t(label)} />}
            </div>
          ))}
        </div>
        {q.scoreSource && <p className="hint">{t("qualityScoreFrom", { source: q.scoreSource })}</p>}
        {q.error && <p className="hint" role="status">{t("qualityUnavailable")} · <bdi>{q.error}</bdi></p>}
        <div className="quality-threat">
          <div><span>{t("qualityThreat")}</span><strong data-tone={flagged ? "bad" : ""}>{t(threat)}</strong></div>
          <span>{t("qualityAttackCount")} <bdi>{q.attackCount?.toLocaleString() ?? "—"}</bdi></span>
        </div>
        <dl className="quality-signals">
          {FLAGS.map(([key, label]) => (
            <div key={key}>
              <dt>{t(label)}</dt>
              <dd data-tone={q[key] ? (key === "compromised" ? "bad" : "warn") : ""}>
                {t(q[key] === null ? "qualityUnknown" : q[key] ? "qualityDetected" : "qualityNotDetected")}
              </dd>
            </div>
          ))}
        </dl>
        {(q.network || q.operator) && <p className="hint"><bdi>{[q.operator, q.network].filter(Boolean).join(" · ")}</bdi></p>}
        {q.blocklists.length > 0 && (
          <details className="blocklists">
            <summary className={`blocklists-title ${listed ? "listed" : ""}`}>
              {answered.length ? t("blocklistsListed", { n: listed, m: answered.length }) : t("blocklistsUnknown")}
            </summary>
            <ul>
              {q.blocklists.map((b) => (
                <li key={b.name} className={b.listed === null ? "" : b.listed ? "listed" : "clean"}>
                  <span className="ltr">{b.name}</span>
                  <i>{t(b.listed === null ? "listedUnknown" : b.listed ? "listedYes" : "listedNo")}</i>
                </li>
              ))}
            </ul>
          </details>
        )}
      </div>
      <p className="hint quality-note">{t("qualitySource")}</p>
    </>
  );
}

function GeoRow({ geo, exitIp }: { geo: Geo; exitIp: string }) {
  const t = useT();
  return (
    <>
      <dt>{geo.source}</dt>
      {geo.error ? (
        <dd className="muted">{geo.error}</dd>
      ) : geo.ip !== exitIp ? (
        <dd className="muted">{t("infoOtherExit")} · <bdi>{geo.ip ?? "—"}</bdi></dd>
      ) : (
        <dd className="ltr">{[geo.country, geo.city].filter(Boolean).join(" · ") || "—"}</dd>
      )}
    </>
  );
}
