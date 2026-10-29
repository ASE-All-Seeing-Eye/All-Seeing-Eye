export async function getHealth() {
  const res = await fetch("/api/health");
  if (!res.ok) throw new Error(`Backend antwortet mit ${res.status}`);
  return res.json();
}