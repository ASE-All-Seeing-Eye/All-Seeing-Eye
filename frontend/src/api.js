export async function getHealth() {
  const res = await fetch("/api/health");
  if (!res.ok) throw new Error(`Backend antwortet mit ${res.status}`);
  return res.json();
}

export async function fetchDemoReport() {
  const res = await fetch("http://localhost:8000/api/reports");
  if (!res.ok) {
    throw new Error("Report konnte nicht geladen werden");
  }
  return res.json();
}