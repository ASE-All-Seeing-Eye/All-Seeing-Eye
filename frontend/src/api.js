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

export async function getJobs() {
  const res = await fetch("/api/analysis/jobs");
  if (!res.ok) throw new Error(`Backend antwortet mit ${res.status}`);
  return res.json();
}

export async function getJobAnalyse(jobId) {
  const res = await fetch(`/api/analysis/jobs/${jobId}`);
  if (!res.ok) throw new Error(`Backend antwortet mit ${res.status}`);
  return res.json();
}

export async function startJobQueue() {
  const res = await fetch("/api/jobqueue/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  if (!res.ok) throw new Error(`Backend antwortet mit ${res.status}`);
  return res.json();
}

export async function getJobQueueStatus() {
  const res = await fetch("/api/jobqueue/status");
  if (!res.ok) throw new Error(`Backend antwortet mit ${res.status}`);
  return res.json();
}