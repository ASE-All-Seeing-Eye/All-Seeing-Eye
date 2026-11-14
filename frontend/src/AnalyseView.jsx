import { useEffect, useState } from "react";
import { getJobs, getJobAnalyse, startJobQueue, getJobQueueStatus } from "./api";

const SCHWEREGRAD = {
  CRITICAL: { label: "KRITISCH", farbe: "#f43225" },
  HIGH: { label: "HOCH", farbe: "#ff8a3d" },
  MEDIUM: { label: "MITTEL", farbe: "#f5c542" },
  LOW: { label: "NIEDRIG", farbe: "#3ddc84" },
  INFO: { label: "INFO", farbe: "#45dcff" },
};

const REIHENFOLGE = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export default function AnalyseView() {
  const [jobs, setJobs] = useState(null);
  const [jobId, setJobId] = useState(null);
  const [analyse, setAnalyse] = useState(null);
  const [fehler, setFehler] = useState(null);
  const [auswahl, setAuswahl] = useState(0);
  const [geraetFilter, setGeraetFilter] = useState("alle");
  const [stufenFilter, setStufenFilter] = useState("alle");
  const [queue, setQueue] = useState({ laeuft: false, job_id: null, schritt: null });
  const [queueFehler, setQueueFehler] = useState(null);

  useEffect(() => {
    getJobs()
      .then((liste) => {
        setJobs(liste);
        if (liste.length > 0) setJobId(liste[0].id);
      })
      .catch((e) => setFehler(e.message));
    getJobQueueStatus().then(setQueue).catch(() => {});
  }, []);

  useEffect(() => {
    if (jobId === null) return;
    setAnalyse(null);
    setAuswahl(0);
    setGeraetFilter("alle");
    setStufenFilter("alle");
    getJobAnalyse(jobId).then(setAnalyse).catch((e) => setFehler(e.message));
  }, [jobId]);

  useEffect(() => {
    if (!queue.laeuft) return;
    const timer = setInterval(() => {
      getJobQueueStatus()
        .then((s) => {
          if (s.laeuft) {
            setQueue(s);
          } else {
            const fertig = queue.job_id;
            setQueue(s);
            getJobs().then((liste) => {
              setJobs(liste);
              setJobId(fertig);
            });
          }
        })
        .catch((e) => setQueueFehler(e.message));
    }, 3000);
    return () => clearInterval(timer);
  }, [queue.laeuft, queue.job_id]);

  function jobStarten() {
    setQueueFehler(null);
    startJobQueue()
      .then((antwort) => setQueue({ laeuft: true, job_id: antwort.job_id, schritt: "Wird gestartet" }))
      .catch((e) => setQueueFehler(e.message));
  }

  if (fehler) {
    return <Rahmen><p className="hinweis fehler">Fehler beim Laden: {fehler}</p></Rahmen>;
  }
  if (!jobs) {
    return <Rahmen><p className="hinweis">Lade Analysen …</p></Rahmen>;
  }
  if (jobs.length === 0) {
    return (
      <Rahmen>
        <Kopf />
        <p className="hinweis" style={{ marginBottom: 20 }}>Noch keine Analyse vorhanden.</p>
        <div style={{ textAlign: "left" }}>
          <JobQueueKnopf queue={queue} fehler={queueFehler} onStart={jobStarten} />
        </div>
      </Rahmen>
    );
  }

  return (
    <Rahmen>
      <Kopf />

      <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap", marginBottom: 20 }}>
        <span className="karten-titel" style={{ margin: 0 }}>Durchlauf</span>
        <select className="auswahlbox" value={jobId ?? ""} onChange={(e) => setJobId(Number(e.target.value))}>
          {jobs.map((job) => (
            <option key={job.id} value={job.id}>
              Job {job.id} – {datum(job.created_at)}
            </option>
          ))}
        </select>
        {analyse && <div className="info-kasten">Status: <b>{analyse.job.status}</b></div>}
        <div style={{ marginLeft: "auto" }}>
          <JobQueueKnopf queue={queue} fehler={queueFehler} onStart={jobStarten} />
        </div>
      </div>

      {analyse?.job.error_message && <div className="warnung">⚠ {analyse.job.error_message}</div>}

      {!analyse ? <p className="hinweis">Lade Durchlauf …</p> : (
        <JobInhalt
          analyse={analyse}
          auswahl={auswahl}
          setAuswahl={setAuswahl}
          geraetFilter={geraetFilter}
          setGeraetFilter={setGeraetFilter}
          stufenFilter={stufenFilter}
          setStufenFilter={setStufenFilter}
        />
      )}
    </Rahmen>
  );
}

function Kopf() {
  return (
    <div>
      <p className="oberzeile">Analyse / Befunde</p>
      <h1 className="seitentitel">Risiken <span>erkennen</span></h1>
      <p className="untertitel">Was Regeln und KI in den Konfigurationen gefunden haben.</p>
    </div>
  );
}

function JobInhalt({ analyse, auswahl, setAuswahl, geraetFilter, setGeraetFilter, stufenFilter, setStufenFilter }) {
  const alleFunde = analyse.findings;
  const stats = analyse.statistik;
  const gesamt = alleFunde.length;

  const geraeteNamen = [...new Set(alleFunde.map((f) => f.device_name))].sort();

  const funde = alleFunde.filter(
    (f) =>
      (geraetFilter === "alle" || f.device_name === geraetFilter) &&
      (stufenFilter === "alle" || f.severity === stufenFilter)
  );
  const aktuell = funde[auswahl];

  return (
    <>
      <div className="karte">
        <div className="karten-titel">Analyseergebnis</div>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <span style={{ fontSize: 14, whiteSpace: "nowrap", color: "var(--text-hell)" }}>
            <b style={{ color: "var(--text)", fontSize: 22 }}>{gesamt}</b> Findings gefunden
          </span>
          <div className="balken-spur" style={{ display: "flex", height: 10 }}>
            {REIHENFOLGE.map((stufe) =>
              stats[stufe] > 0 ? (
                <div
                  key={stufe}
                  title={`${SCHWEREGRAD[stufe].label}: ${stats[stufe]}`}
                  style={{ width: `${(stats[stufe] / gesamt) * 100}%`, background: SCHWEREGRAD[stufe].farbe }}
                />
              ) : null
            )}
          </div>
        </div>

        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginTop: 16 }}>
          <FilterKnopf aktiv={stufenFilter === "alle"} onClick={() => { setStufenFilter("alle"); setAuswahl(0); }}>
            ALLE ({gesamt})
          </FilterKnopf>
          {REIHENFOLGE.map((stufe) => (
            <FilterKnopf
              key={stufe}
              aktiv={stufenFilter === stufe}
              farbe={SCHWEREGRAD[stufe].farbe}
              onClick={() => { setStufenFilter(stufe); setAuswahl(0); }}
            >
              {SCHWEREGRAD[stufe].label} ({stats[stufe] ?? 0})
            </FilterKnopf>
          ))}

          <select
            className="auswahlbox"
            value={geraetFilter}
            onChange={(e) => { setGeraetFilter(e.target.value); setAuswahl(0); }}
            style={{ marginLeft: "auto" }}
          >
            <option value="alle">Alle Geräte</option>
            {geraeteNamen.map((name) => (
              <option key={name} value={name}>{name}</option>
            ))}
          </select>
        </div>
      </div>

      {gesamt === 0 ? null : (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginTop: 20 }}>
          <div className="karte">
            <div className="karten-titel">Findings ({funde.length})</div>
            {funde.length === 0 && <p className="hinweis" style={{ fontSize: 14 }}>Kein Finding passt zum Filter.</p>}
            {funde.map((fund, index) => {
              const s = SCHWEREGRAD[fund.severity] || SCHWEREGRAD.INFO;
              return (
                <button
                  key={fund.id}
                  className={index === auswahl ? "finding aktiv" : "finding"}
                  onClick={() => setAuswahl(index)}
                  style={{ borderLeftColor: s.farbe }}
                >
                  <div>
                    <div className="finding-titel">{fund.title}</div>
                    <div className="finding-info">
                      <span style={{ color: s.farbe, fontFamily: "var(--mono)", fontWeight: 700 }}>{s.label}</span>
                      {" · "}{fund.device_name} · {fund.category}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>

          <div className="karte">
            <div className="karten-titel">Finding-Details</div>
            {aktuell ? <Details fund={aktuell} /> : <p className="hinweis" style={{ fontSize: 14 }}>Kein Finding ausgewählt.</p>}
          </div>
        </div>
      )}
    </>
  );
}

function Details({ fund }) {
  const s = SCHWEREGRAD[fund.severity] || SCHWEREGRAD.INFO;

  return (
    <div>
      <span className="stufe" style={{ color: s.farbe, borderColor: s.farbe, marginBottom: 12 }}>{s.label}</span>
      <div style={{ fontWeight: 700, fontSize: 20, margin: "12px 0 8px" }}>{fund.title}</div>

      <div style={{ fontSize: 13, color: "var(--gedaempft)", marginBottom: 20 }}>
        Gerät: <b style={{ color: "var(--text)" }}>{fund.device_name}</b> · Erkannt durch: {fund.detected_by === "llm" ? "KI" : "Regel"}
        {fund.rule_id && <> · <span style={{ fontFamily: "var(--mono)" }}>REGEL-{String(fund.rule_id).padStart(3, "0")}</span></>}
      </div>

      <Abschnitt titel="Beschreibung">{fund.description}</Abschnitt>
      <Abschnitt titel="Warum ist das ein Problem?">{fund.reason}</Abschnitt>

      <div style={{ marginBottom: 18 }}>
        <div className="feld-titel">Beleg aus der Konfiguration</div>
        <pre className="beleg">{fund.evidence || "Kein Beleg vorhanden"}</pre>
      </div>

      <div style={{ padding: "14px 16px", borderLeft: "3px solid var(--akzent)", background: "var(--flaeche-hell)" }}>
        <div className="feld-titel">Handlungsempfehlung</div>
        <div style={{ fontWeight: 600, fontSize: 14 }}>{fund.recommendation}</div>
      </div>
    </div>
  );
}

function FilterKnopf({ aktiv, onClick, farbe, children }) {
  const f = farbe || "#45dcff";
  return (
    <button
      className="filter-knopf"
      onClick={onClick}
      style={{
        borderColor: aktiv ? f : undefined,
        background: aktiv ? f : undefined,
        color: aktiv ? "#05090d" : farbe,
      }}
    >
      {children}
    </button>
  );
}

function Abschnitt({ titel, children }) {
  return (
    <div style={{ marginBottom: 18 }}>
      <div className="feld-titel">{titel}</div>
      <div style={{ fontSize: 14, lineHeight: 1.6, color: "var(--text-hell)" }}>{children}</div>
    </div>
  );
}

function JobQueueKnopf({ queue, fehler, onStart }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
      {queue.laeuft && <span style={{ fontSize: 12, color: "var(--gedaempft)" }}>{queue.schritt}</span>}
      {fehler && <span style={{ fontSize: 12, color: "var(--rot)" }}>{fehler}</span>}
      <button className="knopf" onClick={onStart} disabled={queue.laeuft}>
        {queue.laeuft ? `Job ${queue.job_id} läuft …` : "Scan starten"}
      </button>
    </div>
  );
}

function Rahmen({ children }) {
  return (
    <div className="seite">
      <div className="seite-inhalt">{children}</div>
    </div>
  );
}

function datum(text) {
  return new Date(text).toLocaleString("de-AT", { dateStyle: "short", timeStyle: "short" });
}