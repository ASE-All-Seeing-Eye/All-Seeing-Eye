import { useEffect, useState } from "react";
import { getInventory } from "./api";

const HERSTELLER_FARBE = {
  cisco: { hell: "#dbeafe", rand: "#2563eb" },
  fortinet: { hell: "#fee2e2", rand: "#dc2626" },
};

export default function InventoryView() {
  const [geraete, setGeraete] = useState([]);
  const [fehler, setFehler] = useState(null);
  const [geladen, setGeladen] = useState(false);
  const [suche, setSuche] = useState("");

  useEffect(() => {
    getInventory()
      .then((daten) => {
        setGeraete(daten);
        setGeladen(true);
      })
      .catch((e) => setFehler(e.message));
  }, []);

  if (fehler) {
    return <Rahmen><p style={{ color: "#b91c1c" }}>Fehler beim Laden: {fehler}</p></Rahmen>;
  }
  if (!geladen) {
    return <Rahmen><p>Lade Inventar …</p></Rahmen>;
  }

  const suchtext = suche.toLowerCase();
  const gefiltert = geraete.filter((geraet) =>
    [geraet.hostname, geraet.management_ip, geraet.vendor, geraet.model, geraet.os_type]
      .some((wert) => String(wert ?? "").toLowerCase().includes(suchtext))
  );

  const anzahlProHersteller = {};
  for (const geraet of geraete) {
    const name = geraet.vendor || "Unbekannt";
    anzahlProHersteller[name] = (anzahlProHersteller[name] || 0) + 1;
  }

  return (
    <div style={{ minHeight: "100vh", fontFamily: "system-ui, sans-serif", background: "#f4f4f5" }}>
      <main style={{ padding: 32, maxWidth: 1100, margin: "0 auto" }}>
        <h1 style={{ margin: "0 0 24px", fontSize: 30 }}>Inventar</h1>

        <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginBottom: 20 }}>
          <Infokasten text={`Geräte gesamt: ${geraete.length}`} />
          {Object.entries(anzahlProHersteller).map(([hersteller, anzahl]) => (
            <Infokasten key={hersteller} text={`${hersteller}: ${anzahl}`} />
          ))}
        </div>

        <div style={karte}>
          <input
            type="text"
            placeholder="Suchen nach Hostname, IP, Hersteller …"
            value={suche}
            onChange={(e) => setSuche(e.target.value)}
            style={{
              width: "100%",
              boxSizing: "border-box",
              padding: "10px 14px",
              fontSize: 14,
              border: "1px solid #d4d4d8",
              borderRadius: 10,
              marginBottom: 16,
            }}
          />

          {gefiltert.length === 0 ? (
            <p style={{ color: "#52525b" }}>
              {geraete.length === 0 ? "Noch keine Geräte in der Datenbank." : "Kein Gerät passt zur Suche."}
            </p>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
                <thead>
                  <tr style={{ textAlign: "left", color: "#52525b", borderBottom: "2px solid #e4e4e7" }}>
                    <th style={zelle}>Hostname</th>
                    <th style={zelle}>Management-IP</th>
                    <th style={zelle}>Hersteller</th>
                    <th style={zelle}>Modell</th>
                    <th style={zelle}>Betriebssystem</th>
                    <th style={zelle}>Version</th>
                  </tr>
                </thead>
                <tbody>
                  {gefiltert.map((geraet) => (
                    <tr key={geraet.id} style={{ borderBottom: "1px solid #e4e4e7" }}>
                      <td style={{ ...zelle, fontWeight: 600 }}>{geraet.hostname || "–"}</td>
                      <td style={{ ...zelle, fontFamily: "Consolas, monospace" }}>{geraet.management_ip}</td>
                      <td style={zelle}><HerstellerBadge name={geraet.vendor} /></td>
                      <td style={zelle}>{geraet.model || "–"}</td>
                      <td style={zelle}>{geraet.os_type || "–"}</td>
                      <td style={zelle}>{geraet.os_version || "–"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

function HerstellerBadge({ name }) {
  if (!name) return "–";
  const farbe = HERSTELLER_FARBE[name.toLowerCase()] || { hell: "#e4e4e7", rand: "#71717a" };
  return (
    <span
      style={{
        background: farbe.hell,
        color: farbe.rand,
        border: `2px solid ${farbe.rand}`,
        borderRadius: 6,
        padding: "2px 10px",
        fontSize: 12,
        fontWeight: 700,
      }}
    >
      {name}
    </span>
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

const zelle = { padding: "10px 12px" };