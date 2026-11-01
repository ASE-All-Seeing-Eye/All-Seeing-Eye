export async function getHealth() {
  const res = await fetch("/api/health");
  if (!res.ok) throw new Error(`Backend antwortet mit ${res.status}`);
  return res.json();
}

export async function getInventory() {
  const res = await fetch("/api/inventory");
  if (!res.ok) throw new Error(`Backend antwortet mit ${res.status}`);
  return res.json();
}

export async function getTopology() {
  const res = await fetch("/api/topology");
  if (!res.ok) throw new Error(`Backend antwortet mit ${res.status}`);
  return res.json();
}