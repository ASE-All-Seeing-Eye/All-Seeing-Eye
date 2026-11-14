import { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import { getInventory, getJobs, getJobAnalyse, getTopology } from "./api";
import { STIL, mitGeraetetyp } from "./TopologyView.jsx";

const SCHWEREGRAD = {
  CRITICAL: { label: "Kritisch", farbe: "#f43225" },
  HIGH: { label: "Hoch", farbe: "#ff8a3d" },
  MEDIUM: { label: "Mittel", farbe: "#f5c542" },
  LOW: { label: "Niedrig", farbe: "#3ddc84" },
  INFO: { label: "Info", farbe: "#45dcff" },
};

const STATUS = {
  ok: { text: "Erfolgreich", farbe: "#3ddc84" },
  done: { text: "Erfolgreich", farbe: "#3ddc84" },
  partial: { text: "Teilweise", farbe: "#f5c542" },
  failed: { text: "Fehlgeschlagen", farbe: "#f43225" },
  running: { text: "Läuft", farbe: "#45dcff" },
  pending: { text: "Wartet", farbe: "#8ba0a8" },
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
    return <Rahmen><p className="hinweis fehler">Fehler beim Laden: {fehler}</p></Rahmen>;
  }
  if (!daten) {
    return <Rahmen><p className="hinweis">Lade Übersicht …</p></Rahmen>;
  }

  const { geraete, jobs, letzter, analyse } = daten;
  const stats = analyse?.statistik ?? {};
  const anzahlFindings = analyse?.findings.length ?? 0;
  const dringend = (stats.CRITICAL ?? 0) + (stats.HIGH ?? 0);

  return (
    <div className="seite" style={{ height: "calc(100vh - 57px)", minHeight: 0 }}>
      <div
        className="seite-inhalt"
        style={{
          maxWidth: 1164,
          height: "100%",
          boxSizing: "border-box",
          padding: "28px 32px",
          display: "flex",
          flexDirection: "column",
          gap: 20,
        }}
      >
        <div>
          <p className="oberzeile">Übersicht / Netzwerkstatus</p>
          <h1 className="seitentitel" style={{ fontSize: 34 }}>Das Netzwerk <span>auf einen Blick</span></h1>
        </div>

        <div className="kennzahlen" style={{ gridTemplateColumns: "repeat(4, 1fr)", marginBottom: 0 }}>
          <Kachel titel="Geräte" wert={geraete.length} onClick={() => onNavigate("inventar")} hervorgehoben />
          <Kachel titel="Letzter Scan" wert={letzter ? datum(letzter.created_at) : "–"} klein />
          <Kachel titel="Findings" wert={anzahlFindings} onClick={() => onNavigate("analyse")} />
          <Kachel
            titel="Kritisch + Hoch"
            wert={dringend}
            farbe={dringend > 0 ? "#f43225" : undefined}
            onClick={() => onNavigate("analyse")}
          />
        </div>

        <div style={{ flex: 1, minHeight: 0, display: "grid", gridTemplateColumns: "2fr 1fr", gap: 20 }}>
          <div
            className="karte klickbar punkte-hintergrund"
            onClick={() => onNavigate("topologie")}
            style={{ padding: 0, position: "relative", overflow: "hidden" }}
          >
            <div ref={vorschau} style={{ position: "absolute", inset: 0 }} />
            <div className="karten-titel" style={{ position: "absolute", top: 18, left: 20 }}>Topologie</div>
            <div className="karten-titel" style={{ position: "absolute", bottom: 2, right: 20, color: "var(--akzent)" }}>
              Öffnen →
            </div>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 20, minHeight: 0, overflowY: "auto" }}>
            <div className="karte">
              <div className="karten-titel">Findings nach Schweregrad</div>
              {anzahlFindings === 0 ? (
                <p className="hinweis" style={{ fontSize: 14 }}>Keine Findings im letzten Scan.</p>
              ) : (
                Object.entries(SCHWEREGRAD).map(([stufe, s]) => (
                  <Balken key={stufe} label={s.label} farbe={s.farbe} anzahl={stats[stufe] ?? 0} gesamt={anzahlFindings} />
                ))
              )}
            </div>

            <div className="karte" style={{ flex: 1 }}>
              <div className="karten-titel">Letzte Scans</div>
              {jobs.length === 0 ? (
                <p className="hinweis" style={{ fontSize: 14 }}>Noch kein Scan durchgeführt.</p>
              ) : (
                jobs.slice(0, 5).map((job) => {
                  const s = STATUS[job.status] || { text: job.status, farbe: "#8ba0a8" };
                  return (
                    <div key={job.id} className="zeile">
                      <span style={{ color: "var(--text-hell)" }}>
                        <span style={{ fontFamily: "var(--mono)", color: "var(--akzent)" }}>#{job.id}</span>{" "}
                        {datum(job.created_at)}
                      </span>
                      <span style={{ color: s.farbe, fontWeight: 600 }}>{s.text}</span>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Kachel({ titel, wert, farbe, klein, onClick, hervorgehoben }) {
  const klassen = ["kennzahl", hervorgehoben && "hervorgehoben", onClick && "klickbar"].filter(Boolean).join(" ");
  return (
    <div className={klassen} onClick={onClick}>
      <div className="kennzahl-titel">{titel}</div>
      <div className="kennzahl-wert" style={{ fontSize: klein ? 20 : 32, lineHeight: klein ? "32px" : 1, color: farbe }}>
        {wert}
      </div>
    </div>
  );
}

function Balken({ label, farbe, anzahl, gesamt }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12, fontSize: 14 }}>
      <span style={{ width: 70, color: "var(--text-hell)" }}>{label}</span>
      <div className="balken-spur">
        <div style={{ width: `${(anzahl / gesamt) * 100}%`, height: "100%", background: farbe }} />
      </div>
      <span style={{ width: 24, textAlign: "right", fontWeight: 600 }}>{anzahl}</span>
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