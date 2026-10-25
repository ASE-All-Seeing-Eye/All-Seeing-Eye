import { useEffect, useState } from "react";

const API_URL = "/api/reports";

const SCHWEREGRAD = {
  CRITICAL: { label: "KRITISCH", farbe: "#b91c1c", hell: "#fee2e2", rand: "#b91c1c" },
  HIGH: { label: "HOCH", farbe: "#ef4444", hell: "#fee2e2", rand: "#dc2626" },
  MEDIUM: { label: "MITTEL", farbe: "#facc15", hell: "#fef9c3", rand: "#ca8a04" },
  LOW: { label: "NIEDRIG", farbe: "#22c55e", hell: "#dcfce7", rand: "#16a34a" },
};

const REIHENFOLGE = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export default function AnalyseView() {
  const [report, setReport] = useState(null);
  const [fehler, setFehler] = useState(null);
  const [auswahl, setAuswahl] = useState(0);

  useEffect(() => {
    fetch(API_URL)
      .then((antwort) => {
        if (!antwort.ok) throw new Error("Server antwortet mit Status " + antwort.status);
        return antwort.json();
      })
      .then(setReport)
      .catch((e) => setFehler(e.message));
  }, []);

  if (fehler) {
    return <Rahmen><p style={{ color: "#b91c1c" }}>Fehler beim Laden: {fehler}</p></Rahmen>;
  }
  if (!report) {
    return <Rahmen><p>Lade Analyse …</p></Rahmen>;
  }

  const inhalt = report.content;
  const funde = inhalt.findings;
  const stats = inhalt.statistics.by_severity;
  const gesamt = inhalt.statistics.finding_count;
  const aktuell = funde[auswahl];
  const scanDatum = new Date(inhalt.created_at).toLocaleDateString("de-AT");

  return (
    <div style={{ minHeight: "100vh", fontFamily: "system-ui, sans-serif", background: "#f4f4f5" }}>
      <main style={{ padding: 32, maxWidth: 1100, margin: "0 auto" }}>
        <h1 style={{ margin: "0 0 24px", fontSize: 30 }}>Analyse</h1>

        <div style={{ display: "flex", gap: 16, alignItems: "center", marginBottom: 20 }}>
          <Infokasten text={`Analyse-ID: ${inhalt.analysis_id}`} />
          <Infokasten text={`Scan: ${scanDatum}`} />
        </div>

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
            <span style={{ fontSize: 13, color: "#555", whiteSpace: "nowrap" }}>
              {REIHENFOLGE.map((stufe) => `${stats[stufe]} ${SCHWEREGRAD[stufe].label.toLowerCase()}`).join(" | ")}
            </span>
          </div>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginTop: 20 }}>
          <div style={karte}>
            <div style={{ fontWeight: 600, marginBottom: 14 }}>Findings</div>
            {funde.map((fund, index) => {
              const s = SCHWEREGRAD[fund.severity] || SCHWEREGRAD.LOW;
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
                      REGEL-{String(fund.rule_id).padStart(3, "0")} · {fund.category}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>

          <div style={karte}>
            <div style={{ fontWeight: 600, marginBottom: 14 }}>Finding-Details</div>

            {aktuell && <Details fund={aktuell} />}
          </div>
        </div>
      </main>
    </div>
  );
}

function Details({ fund }) {
  const s = SCHWEREGRAD[fund.severity] || SCHWEREGRAD.LOW;
  const evidenz = Object.entries(fund.evidence || {})
    .map(([schluessel, wert]) => `${schluessel}: ${String(wert)}`)
    .join("\n");

  return (
    <div>
      <div style={{ fontWeight: 600, fontSize: 16, marginBottom: 14 }}>{fund.title}</div>

      <div style={{ fontSize: 12, color: "#52525b", marginBottom: 6 }}>REGEL-{String(fund.rule_id).padStart(3, "0")}</div>
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
        <div style={{ fontSize: 12, color: "#52525b", marginBottom: 6 }}>Evidence</div>
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
          {evidenz || "Keine Evidence vorhanden"}
        </pre>
      </div>

      <div style={{ marginTop: 16 }}>
        <div style={{ fontSize: 12, color: "#52525b", marginBottom: 6 }}>Handlungsempfehlung</div>
        <div style={{ fontWeight: 600, fontSize: 14 }}>{fund.recommendation}</div>
      </div>
    </div>
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

function Rahmen({ children }) {
  return <div style={{ padding: 32, fontFamily: "system-ui, sans-serif" }}>{children}</div>;
}

const karte = {
  background: "white",
  border: "1px solid #d4d4d8",
  borderRadius: 16,
  padding: 20,
};
