import { useEffect, useState } from "react";
import { getInventory } from "./api";

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
    return <Rahmen><p className="hinweis fehler">Fehler beim Laden: {fehler}</p></Rahmen>;
  }
  if (!geladen) {
    return <Rahmen><p className="hinweis">Lade Inventar …</p></Rahmen>;
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
    <Rahmen>
      <p className="oberzeile">Inventar / Datenbank</p>
      <h1 className="seitentitel">Erfasste <span>Geräte</span></h1>
      <p className="untertitel">Alle Geräte, die der Scanner im Netzwerk gefunden hat.</p>

      <div className="kennzahlen">
        <Kennzahl titel="Geräte gesamt" wert={geraete.length} hervorgehoben />
        {Object.entries(anzahlProHersteller).map(([hersteller, anzahl]) => (
          <Kennzahl key={hersteller} titel={hersteller} wert={anzahl} />
        ))}
      </div>

      <div className="karte">
        <input
          type="text"
          className="suchfeld"
          placeholder="Suchen nach Hostname, IP, Hersteller …"
          value={suche}
          onChange={(e) => setSuche(e.target.value)}
        />

        {gefiltert.length === 0 ? (
          <p className="hinweis">
            {geraete.length === 0 ? "Noch keine Geräte in der Datenbank." : "Kein Gerät passt zur Suche."}
          </p>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="tabelle">
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>Management-IP</th>
                  <th>Hersteller</th>
                  <th>Modell</th>
                  <th>Betriebssystem</th>
                  <th>Version</th>
                </tr>
              </thead>
              <tbody>
                {gefiltert.map((geraet) => (
                  <tr key={geraet.id}>
                    <td className="hostname">{geraet.hostname || "–"}</td>
                    <td className="ip">{geraet.management_ip}</td>
                    <td><HerstellerBadge name={geraet.vendor} /></td>
                    <td>{geraet.model || "–"}</td>
                    <td>{geraet.os_type || "–"}</td>
                    <td>{geraet.os_version || "–"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Rahmen>
  );
}

function HerstellerBadge({ name }) {
  if (!name) return "–";
  return <span className={`hersteller ${name.toLowerCase()}`}>{name}</span>;
}

function Kennzahl({ titel, wert, hervorgehoben }) {
  return (
    <div className={hervorgehoben ? "kennzahl hervorgehoben" : "kennzahl"}>
      <div className="kennzahl-titel">{titel}</div>
      <div className="kennzahl-wert">{wert}</div>
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
