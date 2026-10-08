let devices = [];

function renderDevices() {
  const box = document.getElementById("device-list");
  const term = document.getElementById("search").value.trim().toLowerCase();
  const rows = devices.filter(d => String(d.source).toLowerCase().includes(term));

  if (!rows.length) {
    box.innerHTML = '<div class="empty">No matching devices/sources.</div>';
    return;
  }

  box.innerHTML = rows.map(d => `
    <button class="device-card" data-source="${esc(d.source)}">
      <div>
        <strong>${esc(d.source)}</strong>
        <div class="sub">Last seen: ${fmt(d.last_seen)}</div>
      </div>
      <div class="device-metrics">
        <span>${d.total_events} events</span>
        <span>${d.successful_logins} successful</span>
        <span>${d.failed_logins} failed</span>
        <span>${d.critical_events} critical</span>
      </div>
    </button>
  `).join("");

  box.querySelectorAll(".device-card").forEach(btn => {
    btn.addEventListener("click", () => openDevice(btn.dataset.source));
  });
}

async function loadDevices() {
  const { data, error } = await sb
    .from("security_device_summary")
    .select("*")
    .order("last_seen", { ascending: false });

  if (error) throw error;
  devices = data || [];
  renderDevices();
}

async function openDevice(source) {
  const detail = document.getElementById("detail");
  detail.classList.remove("hidden");

  document.getElementById("detail-title").textContent = source;
  document.getElementById("detail-summary").textContent = "Loading investigation data...";

  const [events, blocks, alerts] = await Promise.all([
    sb.from("security_events")
      .select("id,user_id,event_type,target,description,severity,source,created_at")
      .eq("source", source)
      .order("created_at", { ascending: false })
      .limit(200),

    sb.from("security_source_block_history")
      .select("source,blocked_until,reason,created_at,unblocked_at")
      .eq("source", source)
      .order("created_at", { ascending: false })
      .limit(100),

    sb.from("security_alerts")
      .select("id,alert_type,severity,title,description,event_count,first_seen,last_seen,status,created_at")
      .eq("source", source)
      .order("created_at", { ascending: false })
      .limit(100)
  ]);

  if (events.error) throw events.error;
  if (blocks.error) throw blocks.error;
  if (alerts.error) throw alerts.error;

  const ev = events.data || [];
  const bl = blocks.data || [];
  const al = alerts.data || [];

  const success = ev.filter(x => x.event_type === "LOGIN_SUCCESS").length;
  const failed = ev.filter(x => x.event_type === "FAILED_LOGIN").length;
  const logouts = ev.filter(x => x.event_type === "LOGOUT").length;
  const blocked = ev.filter(x => x.event_type === "BLOCKED_LOGIN").length;
  const critical = ev.filter(x => x.severity === "CRITICAL").length;

  document.getElementById("detail-summary").textContent =
    `${ev.length} events · ${failed} failed logins · ${bl.length} recorded blocks`;

  document.getElementById("detail-stats").innerHTML = [
    ["Events", ev.length],
    ["Successful logins", success],
    ["Failed attempts", failed],
    ["Logouts", logouts],
    ["Blocked logins", blocked],
    ["Critical events", critical]
  ].map(x => `<div class="card stat"><b>${x[1]}</b><span>${esc(x[0])}</span></div>`).join("");

  document.getElementById("timeline").innerHTML = ev.length ? ev.map(e => `
    <tr>
      <td>${fmt(e.created_at)}</td>
      <td class="m">${esc(e.event_type)}</td>
      <td>${badge(e.severity)}</td>
      <td class="m">${esc(e.user_id || "—")}</td>
      <td>${esc(e.description || "")}</td>
    </tr>
  `).join("") : '<tr><td colspan="5" class="empty">No events.</td></tr>';

  document.getElementById("blocks").innerHTML = bl.length ? bl.map(b => `
    <tr>
      <td>${fmt(b.created_at)}</td>
      <td>${fmt(b.blocked_until)}</td>
      <td>${esc(b.reason)}</td>
      <td>${b.unblocked_at ? fmt(b.unblocked_at) : "Timed / not recorded"}</td>
    </tr>
  `).join("") : '<tr><td colspan="4" class="empty">No recorded blocks.</td></tr>';

  document.getElementById("investigations").innerHTML = al.length ? al.map(a => `
    <div class="card investigation">
      <b>${esc(a.title)}</b> ${badge(a.severity)} ${badge(a.status)}
      <div class="sub">${esc(a.description || "")}</div>
      <div class="sub">Events: ${a.event_count} · First: ${fmt(a.first_seen)} · Last: ${fmt(a.last_seen)}</div>
    </div>
  `).join("") : '<div class="empty">No alerts for this source.</div>';

  detail.scrollIntoView({ behavior: "smooth", block: "start" });
}

document.getElementById("search").addEventListener("input", renderDevices);
document.getElementById("refresh-history").addEventListener("click", async () => {
  try { await loadDevices(); toast("Device history refreshed.", "ok"); }
  catch (e) { console.error(e); toast("Could not load device history.", "error"); }
});
document.getElementById("close-detail").addEventListener("click", () => {
  document.getElementById("detail").classList.add("hidden");
});

(async () => {
  if (!(await requireAnalyst())) return;
  try {
    await loadDevices();
  } catch (e) {
    console.error(e);
    toast("Could not load device history. Run the Phase 3 SQL first.", "error");
  }
})();
