import { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import { getTopology } from "./api";

const ICONS = {
  router: "/icons/router.svg",
  switch: "/icons/switch.svg",
  firewall: "/icons/firewall.svg",
};

const STIL = [
  {
    selector: "node",
    style: {
      label: "data(label)",
      width: 56,
      height: 56,
      shape: "ellipse",
      "background-opacity": 0,
      "background-fit": "contain",
      "background-clip": "none",
      color: "#18181b",
      "font-size": 13,
      "font-weight": 700,
      "text-valign": "bottom",
      "text-margin-y": 4,
    },
  },
  { selector: 'node[typ = "router"]', style: { "background-image": ICONS.router } },
  { selector: 'node[typ = "switch"]', style: { "background-image": ICONS.switch, shape: "round-rectangle" } },
  { selector: 'node[typ = "firewall"]', style: { "background-image": ICONS.firewall } },
  { selector: "node:selected", style: { "overlay-color": "#facc15", "overlay-opacity": 0.3, "overlay-padding": 8 } },
  {
    selector: "edge",
    style: {
      width: 3,
      "line-color": "#334155",
      "curve-style": "bezier",
      "font-size": 10,
      "font-weight": 600,
      color: "#0f172a",
      "text-background-color": "#fef9c3",
      "text-background-opacity": 1,
      "text-background-padding": 3,
      "text-background-shape": "roundrectangle",
      "source-text-offset": 50,
      "target-text-offset": 50,
    },
  },
  { selector: "edge[?source_interface]", style: { "source-label": "data(source_interface)" } },
  { selector: "edge[?target_interface]", style: { "target-label": "data(target_interface)" } },
];

export default function TopologyView() {
  const [daten, setDaten] = useState(null);
  const [fehler, setFehler] = useState(null);
  const [auswahl, setAuswahl] = useState(null);
  const zeichenflaeche = useRef(null);

  useEffect(() => {
    getTopology().then(setDaten).catch((e) => setFehler(e.message));
  }, []);

  useEffect(() => {
    if (!daten || !zeichenflaeche.current) return;

    const cy = cytoscape({
      container: zeichenflaeche.current,
      elements: [...daten.nodes.map(mitGeraetetyp), ...daten.edges],
      style: STIL,
      layout: { name: "breadthfirst", padding: 50, spacingFactor: 1.3, directed: false },
      minZoom: 0.3,
      maxZoom: 2,
    });

    cy.on("tap", "node", (ereignis) => {
      const knoten = ereignis.target;
      const kabel = knoten.connectedEdges().map((kante) => {
        const d = kante.data();
        const vonHier = d.source === knoten.id();
        return {
          id: d.id,
          eigenesInterface: vonHier ? d.source_interface : d.target_interface,
          nachbar: (vonHier ? kante.target() : kante.source()).data("label"),
          nachbarInterface: vonHier ? d.target_interface : d.source_interface,
        };
      });
      setAuswahl({ ...knoten.data(), kabel });
    });
    cy.on("tap", (ereignis) => {
      if (ereignis.target === cy) setAuswahl(null);
    });

    const neuEinpassen = () => {
      cy.resize();
      cy.fit(undefined, 160);
      cy.panBy({ x: -150, y: 0 });
    };
    requestAnimationFrame(neuEinpassen);
    window.addEventListener("resize", neuEinpassen);

    return () => {
      window.removeEventListener("resize", neuEinpassen);
      cy.destroy();
    };
  }, [daten]);

  if (fehler) {
    return <Rahmen><p style={{ color: "#b91c1c" }}>Fehler beim Laden: {fehler}</p></Rahmen>;
  }
  if (!daten) {
    return <Rahmen><p>Lade Topologie …</p></Rahmen>;
  }

  return (
    <div
      style={{
        position: "relative",
        height: "calc(100vh - 57px)",
        overflow: "hidden",
        fontFamily: "system-ui, sans-serif",
        background: "white",
        backgroundImage: "radial-gradient(#d4d4d8 1px, transparent 1px)",
        backgroundSize: "20px 20px",
      }}
    >
      <div ref={zeichenflaeche} style={{ position: "absolute", inset: 0 }} />

      <div style={{ position: "absolute", top: 16, left: 16, display: "flex", gap: 12 }}>
        <Infokasten text={`Geräte: ${daten.nodes.length}`} />
        <Infokasten text={`Verbindungen: ${daten.edges.length}`} />
      </div>

      <div style={{ ...karte, position: "absolute", top: 16, right: 16, width: 280, boxShadow: "0 4px 16px rgba(0,0,0,0.08)" }}>
        <div style={{ fontWeight: 600, marginBottom: 14 }}>Gerät</div>
        {auswahl ? <GeraeteDetails geraet={auswahl} /> : (
          <p style={{ fontSize: 14, color: "#52525b" }}>Klick auf ein Gerät, um Details zu sehen.</p>
        )}

        <div style={{ fontWeight: 600, margin: "24px 0 10px" }}>Legende</div>
        <Legende bild={ICONS.router} text="Router" />
        <Legende bild={ICONS.switch} text="Switch" />
        <Legende bild={ICONS.firewall} text="Firewall" />
      </div>

      {daten.edges.length === 0 && (
        <div
          style={{
            position: "absolute",
            bottom: 16,
            left: 16,
            background: "white",
            border: "1px solid #d4d4d8",
            borderRadius: 10,
            padding: "8px 14px",
            fontSize: 13,
            color: "#52525b",
          }}
        >
          Noch keine Verbindungen in der Datenbank. Sobald der Collector Nachbarn erkennt, erscheinen hier die Kabel.
        </div>
      )}
    </div>
  );
}

function mitGeraetetyp(node) {
  const d = node.data;
  let typ = "router";
  if ((d.vendor || "").toLowerCase() === "fortinet") typ = "firewall";
  else if ((d.label || "").toLowerCase().startsWith("sw")) typ = "switch";
  return { data: { ...d, typ } };
}

function GeraeteDetails({ geraet }) {
  return (
    <div style={{ fontSize: 14, lineHeight: 1.8 }}>
      <div><b>Name:</b> {geraet.label}</div>
      <div><b>IP:</b> {geraet.ip}</div>
      <div><b>Hersteller:</b> {geraet.vendor || "–"}</div>

      <div style={{ fontWeight: 600, marginTop: 14 }}>Verbindungen</div>
      {geraet.kabel.length === 0 ? (
        <div style={{ color: "#52525b" }}>Keine bekannt</div>
      ) : (
        geraet.kabel.map((k) => (
          <div key={k.id} style={{ fontSize: 13, fontFamily: "Consolas, monospace" }}>
            {k.eigenesInterface || "?"} → {k.nachbar} ({k.nachbarInterface || "?"})
          </div>
        ))
      )}
    </div>
  );
}

function Legende({ bild, text }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 13, marginBottom: 6 }}>
      <img src={bild} alt="" style={{ width: 28, height: 28, objectFit: "contain" }} />
      {text}
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