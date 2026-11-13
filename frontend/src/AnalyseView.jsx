import { useEffect, useState } from "react";
import { getJobs, getJobAnalyse, startJobQueue, getJobQueueStatus } from "./api";


const SCHWEREGRAD = {
  CRITICAL: { label: "KRITISCH", farbe: "#b91c1c", hell: "#fee2e2", rand: "#b91c1c" },
  HIGH: { label: "HOCH", farbe: "#ef4444", hell: "#fee2e2", rand: "#dc2626" },
  MEDIUM: { label: "MITTEL", farbe: "#facc15", hell: "#fef9c3", rand: "#ca8a04" },
  LOW: { label: "NIEDRIG", farbe: "#22c55e", hell: "#dcfce7", rand: "#16a34a" },
  INFO: { label: "INFO", farbe: "#3b82f6", hell: "#dbeafe", rand: "#2563eb" },
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
    return <Rahmen><p style={{ color: "#b91c1c" }}>Fehler beim Laden: {fehler}</p></Rahmen>;
  }
  if (!jobs) {
    return <Rahmen><p>Lade Analysen …</p></Rahmen>;
  }
  if (jobs.length === 0) {
    return (
      <Rahmen>
        <p>Noch keine Analyse vorhanden.</p>
        <JobQueueKnopf queue={queue} fehler={queueFehler} onStart={jobStarten} />
      </Rahmen>
    );
  }

  return (
    <div style={{ fontFamily: "system-ui, sans-serif", background: "#f4f4f5" }}>
      <main style={{ padding: 32, maxWidth: 1100, margin: "0 auto" }}>
        <h1 style={{ margin: "0 0 24px", fontSize: 30 }}>Analyse</h1>

        <div style={{ display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap", marginBottom: 20 }}>
          <label style={{ fontSize: 14, fontWeight: 600 }}>
            Durchlauf:{" "}
            <select value={jobId ?? ""} onChange={(e) => setJobId(Number(e.target.value))} style={auswahlbox}>
              {jobs.map((job) => (
                <option key={job.id} value={job.id}>
                  Job {job.id} – {datum(job.created_at)}
                </option>
              ))}
            </select>
          </label>
          {analyse && <Infokasten text={`Ziel: ${analyse.job.target}`} />}
          {analyse && <Infokasten text={`Status: ${analyse.job.status}`} />}
          <div style={{ marginLeft: "auto" }}>
            <JobQueueKnopf queue={queue} fehler={queueFehler} onStart={jobStarten} />
          </div>
        </div>

        {analyse?.job.error_message && (
          <div style={{ ...karte, background: "#fef9c3", borderColor: "#ca8a04", marginBottom: 20, fontSize: 14 }}>
            ⚠️ {analyse.job.error_message}
          </div>
        )}

        {!analyse ? <p>Lade Durchlauf …</p> : (
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
      </main>
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
      <div style={karte}>
        <div style={{ fontWeight: 600, marginBottom: 14 }}>Analyseergebnis</div>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <span style={{ fontSize: 14, whiteSpace: "nowrap" }}>{gesamt} Findings gefunden</span>
          <div style={{ flex: 1, display: "flex", height: 16, borderRadius: 8, overflow: "hidden", background: "#e4e4e7" }}>
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

        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 14 }}>
          <FilterKnopf aktiv={stufenFilter === "alle"} onClick={() => { setStufenFilter("alle"); setAuswahl(0); }}>
            Alle ({gesamt})
          </FilterKnopf>
          {REIHENFOLGE.map((stufe) => (
            <FilterKnopf
              key={stufe}
              aktiv={stufenFilter === stufe}
              farbe={SCHWEREGRAD[stufe]}
              onClick={() => { setStufenFilter(stufe); setAuswahl(0); }}
            >
              {SCHWEREGRAD[stufe].label} ({stats[stufe] ?? 0})
            </FilterKnopf>
          ))}

          <select
            value={geraetFilter}
            onChange={(e) => { setGeraetFilter(e.target.value); setAuswahl(0); }}
            style={{ ...auswahlbox, marginLeft: "auto" }}
          >
            <option value="alle">Alle Geräte</option>
            {geraeteNamen.map((name) => (
              <option key={name} value={name}>{name}</option>
            ))}
          </select>
        </div>
      </div>

      {gesamt === 0 ? (
        <p style={{ color: "#52525b", marginTop: 20 }}>In diesem Durchlauf wurden keine Findings gespeichert.</p>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginTop: 20 }}>
          <div style={karte}>
            <div style={{ fontWeight: 600, marginBottom: 14 }}>Findings ({funde.length})</div>
            {funde.length === 0 && <p style={{ fontSize: 14, color: "#52525b" }}>Kein Finding passt zum Filter.</p>}
            {funde.map((fund, index) => {
              const s = SCHWEREGRAD[fund.severity] || SCHWEREGRAD.INFO;
              const aktiv = index === auswahl;
              return (
                <button
                  key={fund.id}
                  onClick={() => setAuswahl(index)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 12,
                    width: "100%",
                    textAlign: "left",
                    background: s.hell,
                    border: `2px solid ${s.rand}`,
                    borderRadius: 10,
                    padding: "12px 14px",
                    marginBottom: 10,
                    cursor: "pointer",
                    boxShadow: aktiv ? `0 0 0 3px ${s.rand}55` : "none",
                    color: "#18181b",
                  }}
                >
                  <span style={{ width: 10, height: 10, borderRadius: "50%", background: s.rand, flexShrink: 0 }} />
                  <div>
                    <div style={{ fontWeight: 600, fontSize: 15 }}>{fund.title}</div>
                    <div style={{ fontSize: 12, color: "#52525b", marginTop: 2 }}>
                      {fund.device_name} · {fund.category}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>

          <div style={karte}>
            <div style={{ fontWeight: 600, marginBottom: 14 }}>Finding-Details</div>
            {aktuell ? <Details fund={aktuell} /> : <p style={{ fontSize: 14, color: "#52525b" }}>Kein Finding ausgewählt.</p>}
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
      <div style={{ fontWeight: 600, fontSize: 16, marginBottom: 10 }}>{fund.title}</div>

      <div style={{ fontSize: 12, color: "#52525b", marginBottom: 8 }}>
        Gerät: <b>{fund.device_name}</b> · Erkannt durch: {fund.detected_by === "llm" ? "KI" : "Regel"}
        {fund.rule_id && <> · REGEL-{String(fund.rule_id).padStart(3, "0")}</>}
      </div>

      <span
        style={{
          display: "inline-block",
          background: s.hell,
          color: s.rand,
          border: `2px solid ${s.rand}`,
          borderRadius: 6,
          padding: "4px 12px",
          fontSize: 12,
          fontWeight: 700,
          marginBottom: 18,
        }}
      >
        {s.label}
      </span>

      <Abschnitt titel="Beschreibung">{fund.description}</Abschnitt>
      <Abschnitt titel="Warum ist das ein Problem?">{fund.reason}</Abschnitt>

      <div style={{ marginTop: 16 }}>
        <div style={{ fontSize: 12, color: "#52525b", marginBottom: 6 }}>Beleg aus der Konfiguration</div>
        <pre
          style={{
            background: "#e4e4e7",
            borderRadius: 8,
            padding: 12,
            margin: 0,
            fontSize: 13,
            whiteSpace: "pre-wrap",
            fontFamily: "Consolas, monospace",
          }}
        >
          {fund.evidence || "Kein Beleg vorhanden"}
        </pre>
      </div>

      <div style={{ marginTop: 16 }}>
        <div style={{ fontSize: 12, color: "#52525b", marginBottom: 6 }}>Handlungsempfehlung</div>
        <div style={{ fontWeight: 600, fontSize: 14 }}>{fund.recommendation}</div>
      </div>
    </div>
  );
}

function FilterKnopf({ aktiv, onClick, farbe, children }) {
  const rand = farbe ? farbe.rand : "#18181b";
  return (
    <button
      onClick={onClick}
      style={{
        border: `2px solid ${rand}`,
        background: aktiv ? rand : "white",
        color: aktiv ? "white" : rand,
        borderRadius: 999,
        padding: "4px 12px",
        fontSize: 12,
        fontWeight: 700,
        cursor: "pointer",
      }}
    >
      {children}
    </button>
  );
}

function Abschnitt({ titel, children }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontSize: 12, color: "#52525b", marginBottom: 4 }}>{titel}</div>
      <div style={{ fontSize: 14, lineHeight: 1.5 }}>{children}</div>
    </div>
  );
}

function Infokasten({ text }) {
  return (
    <div style={{ background: "white", border: "1px solid #d4d4d8", borderRadius: 10, padding: "10px 16px", fontSize: 14 }}>
      {text}
    </div>
  );
}


function JobQueueKnopf({ queue, fehler, onStart }) {
  return (
    <div style={{ textAlign: "right" }}>
      <button
        onClick={onStart}
        disabled={queue.laeuft}
        style={{
          background: queue.laeuft ? "#a1a1aa" : "#18181b",
          color: "white",
          border: "none",
          borderRadius: 10,
          padding: "10px 18px",
          fontSize: 14,
          fontWeight: 600,
          cursor: queue.laeuft ? "default" : "pointer",
        }}
      >
        {queue.laeuft ? `Job ${queue.job_id} läuft …` : "Kompletten Scan starten"}
      </button>
      {queue.laeuft && <div style={{ fontSize: 12, color: "#52525b", marginTop: 6 }}>{queue.schritt}</div>}
      {fehler && <div style={{ fontSize: 12, color: "#b91c1c", marginTop: 6 }}>{fehler}</div>}
    </div>
  );
}

function Rahmen({ children }) {
  return <div style={{ padding: 32, fontFamily: "system-ui, sans-serif" }}>{children}</div>;
}

function datum(text) {
  return new Date(text).toLocaleString("de-AT", { dateStyle: "short", timeStyle: "short" });
}

const karte = {
  background: "white",
  border: "1px solid #d4d4d8",
  borderRadius: 16,
  padding: 20,
};

const auswahlbox = {
  padding: "8px 12px",
  fontSize: 14,
  border: "1px solid #d4d4d8",
  borderRadius: 8,
  background: "white",
};