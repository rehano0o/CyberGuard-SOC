let incidentList = [];
async function fetchIncidents() {
  const { data, error } = await sb.from("security_incidents").select("*, security_alerts(title,source,alert_type,event_count)").order("created_at", { ascending: false });
  if (error) throw error; return data;
}
async function updateIncidentStatus(id, status) {
  const { error } = await sb.from("security_incidents").update({ status, updated_at: new Date().toISOString() }).eq("id", id);
  if (error) throw error;
}
async function blockSource(source) {
  const { data, error } = await sb.rpc("block_security_source", { p_source: source, p_minutes: 15 });
  if (error) throw error;
  if (data === false) { toast("This source is trusted and cannot be blocked.", "error"); return false; }
  toast(`Source ${source} blocked for 15 minutes.`);
  return true;
}
async function render() {
  try {
    incidentList = await fetchIncidents();
    document.getElementById("incidents").innerHTML = incidentList.length ? incidentList.map(i => {
      const next = { NEW: ["INVESTIGATE", "INVESTIGATING"], INVESTIGATING: ["RESOLVE", "RESOLVED"] }[i.status];
      const act = next ? `<button class="btn" data-act="status" data-id="${i.id}" data-next="${next[1]}">${next[0]}</button>` : '<span class="m">CLOSED</span>';
      const a = i.security_alerts || {};
      const canContain = i.status === "INVESTIGATING" && a.alert_type === "BRUTE_FORCE";
      const block = canContain ? `<button class="btn danger" data-act="block" data-id="${i.id}">🛡 BLOCK SOURCE · 15 MIN</button>` : '';
      return `<tr><td class="m">${esc(i.id.slice(0, 8))}</td><td>${esc(i.title)}</td><td>${badge(i.severity)}</td><td>${esc(a.title || "")} <span class="m">(${esc(a.source || "")})</span></td><td>${badge(i.status)}</td><td>${fmt(i.created_at)}</td><td>${fmt(i.updated_at)}</td><td>${act} ${block}</td></tr>`;
    }).join("") : '<tr><td colspan="8" class="empty">No incidents yet.</td></tr>';
  } catch (e) { console.error(e); toast("Could not load incidents. Please try again.", "error"); }
}
document.getElementById("incidents").addEventListener("click", async ev => {
  const b = ev.target.closest("button[data-act]"); if (!b) return;
  b.disabled = true;
  try {
    const incident = incidentList.find(i => i.id === b.dataset.id);
    if (b.dataset.act === "status") {
      await updateIncidentStatus(b.dataset.id, b.dataset.next);
      toast("Incident " + b.dataset.next.toLowerCase() + ".");
    } else if (b.dataset.act === "block") {
      const source = incident?.security_alerts?.source;
      if (!source) throw new Error("Incident source not found");
      await blockSource(source);
    }
  } catch (e) { console.error(e); toast(e.message || "Action failed. Please try again.", "error"); }
  await render();
});
(async () => { if (await requireAnalyst()) render(); })();
