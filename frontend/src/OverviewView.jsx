import { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import { getInventory, getJobs, getJobAnalyse, getTopology } from "./api";
import { STIL, mitGeraetetyp } from "./TopologyView.jsx";

const SCHWEREGRAD = {
  CRITICAL: { label: "Kritisch", farbe: "#b91c1c" },
  HIGH: { label: "Hoch", farbe: "#ef4444" },
  MEDIUM: { label: "Mittel", farbe: "#facc15" },
  LOW: { label: "Niedrig", farbe: "#22c55e" },
  INFO: { label: "Info", farbe: "#3b82f6" },
};

const STATUS = {
  ok: { text: "Erfolgreich", farbe: "#16a34a" },
  done: { text: "Erfolgreich", farbe: "#16a34a" },
  partial: { text: "Teilweise", farbe: "#ca8a04" },
  failed: { text: "Fehlgeschlagen", farbe: "#b91c1c" },
  running: { text: "Läuft", farbe: "#2563eb" },
  pending: { text: "Wartet", farbe: "#52525b" },
};

export default function OverviewView({ onNavigate }) {
  const [daten, setDaten] = useState(null);
  const [fehler, setFehler] = useState(null);
  const vorschau = useRef(null);

  useEffect(() => {
    Promise.all([getInventory(), getJobs(), getTopology()])
      .then(async ([geraete, jobs, topologie]) => {
        const letzter = jobs.find((job) => ["ok", "partial", "done"].includes(job.status));
        const analyse = letzter ? await getJobAnalyse(letzter.id) : null;
        setDaten({ geraete, jobs, letzter, analyse, topologie });
      })
      .catch((e) => setFehler(e.message));
  }, []);

  useEffect(() => {
    if (!daten || !vorschau.current) return;

    const cy = cytoscape({
      container: vorschau.current,
      elements: [...daten.topologie.nodes.map(mitGeraetetyp), ...daten.topologie.edges],
      style: STIL,
      layout: { name: "breadthfirst", padding: 30, spacingFactor: 1.2, directed: false },
      userZoomingEnabled: false,
      userPanningEnabled: false,
      autoungrabify: true,
      autounselectify: true,
    });

    const einpassen = () => {
      cy.resize();
      cy.fit(undefined, 40);
    };
    requestAnimationFrame(einpassen);
    window.addEventListener("resize", einpassen);

    return () => {
      window.removeEventListener("resize", einpassen);
      cy.destroy();
    };
  }, [daten]);

  if (fehler) {
    return <Rahmen><p style={{ color: "#b91c1c" }}>Fehler beim Laden: {fehler}</p></Rahmen>;
  }
  if (!daten) {
    return <Rahmen><p>Lade Übersicht …</p></Rahmen>;
  }

  const { geraete, jobs, letzter, analyse } = daten;
  const stats = analyse?.statistik ?? {};
  const anzahlFindings = analyse?.findings.length ?? 0;
  const dringend = (stats.CRITICAL ?? 0) + (stats.HIGH ?? 0);

  return (
    <div
      style={{
        height: "calc(100vh - 57px)",
        boxSizing: "border-box",
        padding: "24px 32px",
        maxWidth: 1164,
        margin: "0 auto",
        display: "flex",
        flexDirection: "column",
        gap: 20,
        fontFamily: "system-ui, sans-serif",
      }}
    >
      <div>
        <h1 style={{ margin: "0 0 4px", fontSize: 28 }}>Übersicht</h1>
        <p style={{ margin: 0, color: "#52525b" }}>Der aktuelle Stand des Netzwerks auf einen Blick.</p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16 }}>
        <Kachel titel="Geräte" wert={geraete.length} onClick={() => onNavigate("inventar")} />
        <Kachel titel="Letzter Scan" wert={letzter ? datum(letzter.created_at) : "–"} klein />
        <Kachel titel="Findings" wert={anzahlFindings} onClick={() => onNavigate("analyse")} />
        <Kachel
          titel="Kritisch + Hoch"
          wert={dringend}
          farbe={dringend > 0 ? "#b91c1c" : undefined}
          onClick={() => onNavigate("analyse")}
        />
      </div>

      <div style={{ flex: 1, minHeight: 0, display: "grid", gridTemplateColumns: "2fr 1fr", gap: 20 }}>
        <div
          onClick={() => onNavigate("topologie")}
          style={{
            ...karte,
            padding: 0,
            position: "relative",
            overflow: "hidden",
            cursor: "pointer",
            backgroundImage: "radial-gradient(#d4d4d8 1px, transparent 1px)",
            backgroundSize: "20px 20px",
          }}
        >
          <div ref={vorschau} style={{ position: "absolute", inset: 0 }} />
          <div style={{ position: "absolute", top: 16, left: 20, fontWeight: 600 }}>Topologie</div>
          <div style={{ position: "absolute", bottom: 14, right: 20, fontSize: 13, color: "#52525b" }}>
            Klicken zum Öffnen →
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 20, minHeight: 0, overflowY: "auto" }}>
          <div style={karte}>
            <div style={{ fontWeight: 600, marginBottom: 14 }}>Findings nach Schweregrad</div>
            {anzahlFindings === 0 ? (
              <p style={{ fontSize: 14, color: "#52525b" }}>Keine Findings im letzten Scan.</p>
            ) : (
              Object.entries(SCHWEREGRAD).map(([stufe, s]) => (
                <Balken key={stufe} label={s.label} farbe={s.farbe} anzahl={stats[stufe] ?? 0} gesamt={anzahlFindings} />
              ))
            )}
          </div>

          <div style={{ ...karte, flex: 1 }}>
            <div style={{ fontWeight: 600, marginBottom: 14 }}>Letzte Scans</div>
            {jobs.length === 0 ? (
              <p style={{ fontSize: 14, color: "#52525b" }}>Noch kein Scan durchgeführt.</p>
            ) : (
              jobs.slice(0, 5).map((job) => {
                const s = STATUS[job.status] || { text: job.status, farbe: "#52525b" };
                return (
                  <div
                    key={job.id}
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      padding: "8px 0",
                      borderBottom: "1px solid #f4f4f5",
                      fontSize: 14,
                    }}
                  >
                    <span>Job {job.id} – {datum(job.created_at)}</span>
                    <span style={{ color: s.farbe, fontWeight: 600 }}>{s.text}</span>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function Kachel({ titel, wert, farbe, klein, onClick }) {
  return (
    <div onClick={onClick} style={{ ...karte, padding: "16px 20px", cursor: onClick ? "pointer" : "default" }}>
      <div style={{ fontSize: 13, color: "#52525b", marginBottom: 6 }}>{titel}</div>
      <div style={{ fontSize: klein ? 18 : 28, fontWeight: 700, color: farbe || "#18181b" }}>{wert}</div>
    </div>
  );
}

function Balken({ label, farbe, anzahl, gesamt }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10, fontSize: 14 }}>
      <span style={{ width: 70 }}>{label}</span>
      <div style={{ flex: 1, height: 12, background: "#e4e4e7", borderRadius: 6, overflow: "hidden" }}>
        <div style={{ width: `${(anzahl / gesamt) * 100}%`, height: "100%", background: farbe }} />
      </div>
      <span style={{ width: 24, textAlign: "right", fontWeight: 600 }}>{anzahl}</span>
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