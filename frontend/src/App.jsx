import { useState } from "react";
import AnalyseView from "./AnalyseView.jsx";
import InventoryView from "./InventoryView.jsx";
import TopologyView from "./TopologyView.jsx";

export default function App() {
  const [seite, setSeite] = useState("analyse");

  return (
    <div>
      <nav style={{ display: "flex", gap: 8, padding: "12px 32px", background: "#18181b" }}>
        <NavKnopf aktiv={seite === "analyse"} onClick={() => setSeite("analyse")}>Analyse</NavKnopf>
        <NavKnopf aktiv={seite === "inventar"} onClick={() => setSeite("inventar")}>Inventar</NavKnopf>
        <NavKnopf aktiv={seite === "topologie"} onClick={() => setSeite("topologie")}>Topologie</NavKnopf>
      </nav>

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