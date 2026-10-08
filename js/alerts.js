let alertList = [], incidentAlertIds = new Set();
async function fetchAlerts() {
  const { data, error } = await sb.from("security_alerts").select("*").order("created_at", { ascending: false });
  if (error) throw error; return data;
}
async function fetchIncidentAlertIds() {
  const { data, error } = await sb.from("security_incidents").select("alert_id");
  if (error) throw error; return new Set(data.map(r => r.alert_id));
}
async function updateAlertStatus(id, status) {
  const { error } = await sb.from("security_alerts").update({ status }).eq("id", id);
  if (error) throw error;
}
// One incident per alert (unique index in the database enforces this).
async function createIncident(alert) {
  const { error } = await sb.from("security_incidents").insert({ alert_id: alert.id, title: alert.title, severity: alert.severity,
    description: `${alert.description} Source: ${alert.source}. Events: ${alert.event_count}.`, status: "NEW" });
  if (error) { if (error.code === "23505") { toast("An incident already exists for this alert.", "error"); return; } throw error; }
  toast("Incident created.");
}
async function render() {
  try {
    [alertList, incidentAlertIds] = await Promise.all([fetchAlerts(), fetchIncidentAlertIds()]);
    document.getElementById("alerts").innerHTML = alertList.length ? alertList.map(a => {
      const next = { OPEN: ["ACKNOWLEDGE", "ACKNOWLEDGED"], ACKNOWLEDGED: ["RESOLVE", "RESOLVED"] }[a.status];
      const step = next ? `<button class="btn" data-act="status" data-id="${a.id}" data-next="${next[1]}">${next[0]}</button>` : '<span class="m">CLOSED</span>';
      const inc = incidentAlertIds.has(a.id) ? '<button class="btn" disabled>INCIDENT EXISTS</button>' : `<button class="btn" data-act="incident" data-id="${a.id}">CREATE INCIDENT</button>`;
      return `<tr><td class="m">${esc(a.alert_type)}</td><td>${badge(a.severity)}</td><td>${esc(a.title)}</td><td class="m">${esc(a.source)}</td><td>${a.event_count}</td><td>${fmt(a.first_seen)}</td><td>${fmt(a.last_seen)}</td><td>${badge(a.status)}</td><td>${step} ${inc}</td></tr>`;
    }).join("") : '<tr><td colspan="9" class="empty">No alerts yet.</td></tr>';
  } catch (e) { console.error(e); toast("Could not load alerts. Please try again.", "error"); }
}
document.getElementById("alerts").addEventListener("click", async ev => {
  const b = ev.target.closest("button[data-act]"); if (!b) return;
  b.disabled = true;
  try {
    if (b.dataset.act === "status") { await updateAlertStatus(b.dataset.id, b.dataset.next); toast("Alert " + b.dataset.next.toLowerCase() + "."); }
    else await createIncident(alertList.find(a => a.id === b.dataset.id));
  } catch (e) { console.error(e); toast("Action failed. Please try again.", "error"); }
  render();
});
document.getElementById("refresh").addEventListener("click", render);
(async () => { if (await requireAnalyst()) render(); })();
