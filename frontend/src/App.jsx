import { useState } from "react";
import OverviewView from "./OverviewView.jsx";
import AnalyseView from "./AnalyseView.jsx";
import InventoryView from "./InventoryView.jsx";
import TopologyView from "./TopologyView.jsx";

export default function App() {
  const [seite, setSeite] = useState("uebersicht");

  return (
    <div>
      <nav className="navigation">
        <button className="nav-logo" onClick={() => setSeite("uebersicht")}>
          <img src="/images/ASE_Logo_weiss.png" alt="" />
          ALL SEEING <span>EYE</span>
        </button>

        <NavKnopf aktiv={seite === "uebersicht"} onClick={() => setSeite("uebersicht")}>Übersicht</NavKnopf>
        <NavKnopf aktiv={seite === "analyse"} onClick={() => setSeite("analyse")}>Analyse</NavKnopf>
        <NavKnopf aktiv={seite === "inventar"} onClick={() => setSeite("inventar")}>Inventar</NavKnopf>
        <NavKnopf aktiv={seite === "topologie"} onClick={() => setSeite("topologie")}>Topologie</NavKnopf>
      </nav>

      {seite === "uebersicht" && <OverviewView onNavigate={setSeite} />}
      {seite === "analyse" && <AnalyseView />}
      {seite === "inventar" && <InventoryView />}
      {seite === "topologie" && <TopologyView />}
    </div>
  );
}

function NavKnopf({ aktiv, onClick, children }) {
  return (
    <button className={aktiv ? "nav-knopf aktiv" : "nav-knopf"} onClick={onClick}>
      {children}
    </button>
  );
}
