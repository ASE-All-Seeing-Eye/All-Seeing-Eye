import { useEffect, useState } from "react";
import { fetchDemoReport } from "./api";

const FARBEN = {
  CRITICAL: "#7f1d1d",
  HIGH: "#dc2626",
  MEDIUM: "#f59e0b",
  LOW: "#16a34a",
};

export default function ReportView() {
  const [report, setReport] = useState(null);
  const [fehler, setFehler] = useState(null);

  useEffect(() => {
    fetchDemoReport().then(setReport).catch((e) => setFehler(e.message));
  }, []);

  if (fehler) return <p>Fehler: {fehler}</p>;
  if (!report) return <p>Lade Report ...</p>;

  const inhalt = report.content;

  return (
    <div style={{ maxWidth: 800, margin: "0 auto", padding: 16 }}>
      <h1>Sicherheitsbericht</h1>
      <p style={{ color: "#666" }}>
        Erstellt am {new Date(inhalt.created_at).toLocaleString("de-AT")}
      </p>

      <h2>Zusammenfassung</h2>
      <p>{inhalt.summary}</p>

      <h2>Statistik ({inhalt.statistics.finding_count} Funde)</h2>
      <div style={{ display: "flex", gap: 12 }}>
        {Object.entries(inhalt.statistics.by_severity).map(([stufe, anzahl]) => (
          <div
            key={stufe}
            style={{
              background: FARBEN[stufe],
              color: "white",
              padding: "8px 16px",
              borderRadius: 8,
            }}
          >
            {stufe}: {anzahl}
          </div>
        ))}
      </div>

      <h2>Funde</h2>
      {inhalt.findings.map((fund) => (
        <div
          key={fund.id}
          style={{
            borderLeft: `6px solid ${FARBEN[fund.severity]}`,
            padding: 12,
            marginBottom: 12,
            background: "#f5f5f5",
            color: "#222",
          }}
        >
          <h3>
            {fund.title} <small>({fund.severity}, {fund.category})</small>
          </h3>
          <p>{fund.description}</p>
          <p><b>Warum ist das ein Problem?</b> {fund.reason}</p>
          <p><b>Empfehlung:</b> {fund.recommendation}</p>
        </div>
      ))}
    </div>
  );
}