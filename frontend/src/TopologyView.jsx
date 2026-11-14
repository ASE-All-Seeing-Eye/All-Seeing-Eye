import { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import { getTopology } from "./api";

const ICONS = {
  router: "/icons/router.svg",
  switch: "/icons/switch.svg",
  firewall: "/icons/firewall.svg",
};

export const STIL = [
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
      color: "#eefcff",
      "font-family": "Segoe UI, system-ui, sans-serif",
      "font-size": 13,
      "font-weight": 700,
      "text-valign": "bottom",
      "text-margin-y": 6,
    },
  },
  { selector: 'node[typ = "router"]', style: { "background-image": ICONS.router } },
  { selector: 'node[typ = "switch"]', style: { "background-image": ICONS.switch, shape: "round-rectangle" } },
  { selector: 'node[typ = "firewall"]', style: { "background-image": ICONS.firewall } },
  { selector: "node:selected", style: { "overlay-color": "#45dcff", "overlay-opacity": 0.25, "overlay-padding": 8 } },
  {
    selector: "edge",
    style: {
      width: 2,
      "line-color": "#405660",
      "curve-style": "bezier",
      "font-family": "Consolas, monospace",
      "font-size": 10,
      "font-weight": 600,
      color: "#9decff",
      "text-background-color": "#091118",
      "text-background-opacity": 1,
      "text-background-padding": 3,
      "text-border-color": "#213641",
      "text-border-width": 1,
      "text-border-opacity": 1,
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
  const hintergrund = useRef(null);

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

    const punkteMitbewegen = () => {
      if (!hintergrund.current) return;
      const zoom = cy.zoom();
      const pan = cy.pan();
      hintergrund.current.style.backgroundSize = `${20 * zoom}px ${20 * zoom}px`;
      hintergrund.current.style.backgroundPosition = `${pan.x}px ${pan.y}px`;
    };

    cy.on("viewport", punkteMitbewegen);

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
    return <Rahmen><p className="hinweis fehler">Fehler beim Laden: {fehler}</p></Rahmen>;
  }
  if (!daten) {
    return <Rahmen><p className="hinweis">Lade Topologie …</p></Rahmen>;
  }

  return (
    <div
      ref={hintergrund}
      className="punkte-hintergrund"
      style={{
        position: "relative",
        height: "calc(100vh - 57px)",
        overflow: "hidden",
        color: "var(--text)",
        fontFamily: "var(--schrift)",
      }}
    >
      <div ref={zeichenflaeche} style={{ position: "absolute", inset: 0 }} />

      <div style={{ position: "absolute", top: 24, left: 32 }}>
        <p className="oberzeile">Topologie / Netzwerkplan</p>
        <div className="info-kasten">Geräte: <b>{daten.nodes.length}</b></div>
      </div>

      <div className="karte" style={{ position: "absolute", top: 16, right: 16, width: 280 }}>
        <div className="karten-titel">Gerät</div>
        {auswahl ? <GeraeteDetails geraet={auswahl} /> : (
          <p className="hinweis" style={{ fontSize: 14 }}>Klick auf ein Gerät, um Details zu sehen.</p>
        )}

        <div className="karten-titel" style={{ marginTop: 24 }}>Legende</div>
        <Legende bild={ICONS.router} text="Router" />
        <Legende bild={ICONS.switch} text="Switch" />
        <Legende bild={ICONS.firewall} text="Firewall" />
      </div>
    </div>
  );
}

export function mitGeraetetyp(node) {
  const d = node.data;
  const modell = (d.model || "").toLowerCase();
  let typ = "router";
  if ((d.vendor || "").toLowerCase() === "fortinet") typ = "firewall";
  else if (
    d.switch ||
    (d.label || "").toLowerCase().startsWith("sw") ||
    modell.startsWith("c9") ||
    d.os_type === "nxos"
  ) typ = "switch";
  return { data: { ...d, typ } };
}

function GeraeteDetails({ geraet }) {
  return (
    <div style={{ fontSize: 14, lineHeight: 1.8, color: "var(--text-hell)" }}>
      <div style={{ color: "var(--text)", fontSize: 18, fontWeight: 700 }}>{geraet.label}</div>
      <div style={{ fontFamily: "var(--mono)", color: "var(--akzent-weich)" }}>{geraet.ip}</div>
      <div>Hersteller: {geraet.vendor || "–"}</div>

      <div className="karten-titel" style={{ marginTop: 16, marginBottom: 6 }}>Verbindungen</div>
      {geraet.kabel.length === 0 ? (
        <div className="hinweis">Keine bekannt</div>
      ) : (
        geraet.kabel.map((k) => (
          <div key={k.id} style={{ fontSize: 13, fontFamily: "var(--mono)" }}>
            {k.eigenesInterface || "?"} <span style={{ color: "var(--akzent)" }}>→</span> {k.nachbar} ({k.nachbarInterface || "?"})
          </div>
        ))
      )}
    </div>
  );
}

function Legende({ bild, text }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 13, marginBottom: 6, color: "var(--text-hell)" }}>
      <img src={bild} alt="" style={{ width: 28, height: 28, objectFit: "contain" }} />
      {text}
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