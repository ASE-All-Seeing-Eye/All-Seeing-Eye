import { useEffect, useState } from "react";
import { getHealth } from "./api.js";

export default function App() {
  const [status, setStatus] = useState("loading");
  const [message, setMessage] = useState("");

  useEffect(() => {
    getHealth()
      .then((data) => {
        setMessage(data.status);
        setStatus("ok");
      })
      .catch(() => setStatus("error"));
  }, []);

  return (
    <main>
      <h1>All Seeing Eye</h1>

      {status === "loading" && <p>Prüfe Verbindung zum Backend …</p>}
      {status === "ok" && <p className="ok">Backend: {message}</p>}
      {status === "error" && (
        <p className="error">Backend nicht erreichbar. Läuft es auf Port 8000?</p>
      )}
    </main>
  );
}