import { useState } from "react";
import OverviewView from "./OverviewView.jsx";
import AnalyseView from "./AnalyseView.jsx";
import InventoryView from "./InventoryView.jsx";
import TopologyView from "./TopologyView.jsx";

export default function App() {
  const [seite, setSeite] = useState("uebersicht");

  return (
    <div>
      <nav style={{ display: "flex", alignItems: "center", gap: 8, padding: "12px 32px", background: "#18181b" }}>
        <button
          onClick={() => setSeite("uebersicht")}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            background: "transparent",
            border: "none",
            color: "white",
            fontSize: 18,
            fontWeight: 700,
            cursor: "pointer",
            padding: 0,
            marginRight: 24,
          }}
        >
          <img src="/images/ASE_Logo_weiss.png" alt="" style={{ height: 32 }} />
          All Seeing Eye
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
    <button
      onClick={onClick}
      style={{
        background: aktiv ? "white" : "transparent",
        color: aktiv ? "#18181b" : "white",
        border: "none",
        borderRadius: 8,
        padding: "8px 16px",
        fontSize: 14,
        fontWeight: 600,
        cursor: "pointer",
      }}
    >
      {children}
    </button>
  );
}