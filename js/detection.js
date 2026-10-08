// Rule-based detection. Works ONLY on real rows in security_events; it never inserts events.
const RULES = [
  { type: "BRUTE_FORCE", severity: "HIGH", title: "Possible Brute Force Attack", threshold: 5, windowMs: 5 * 60000,
    description: "Multiple failed login attempts detected from the same source." },
  { type: "REPEATED_FAILED_LOGIN", severity: "MEDIUM", title: "Repeated Failed Login Attempts", threshold: 3, windowMs: 2 * 60000,
    description: "Multiple failed authentication attempts detected from the same source." }
];

// Count real FAILED_LOGIN rows from this source inside the rule's window; alert if threshold reached.
async function evaluateRule(rule, source, refTime) {
  const since = new Date(refTime.getTime() - rule.windowMs).toISOString();
  const { data, error } = await sb.from("security_events").select("created_at")
    .eq("event_type", "FAILED_LOGIN").eq("source", source).gte("created_at", since).order("created_at", { ascending: true });
  if (error) throw error;
  if (data.length < rule.threshold) return null;
  return createOrUpdateAlert(rule, source, data.length, data[0].created_at, data[data.length - 1].created_at);
}

// One ACTIVE (OPEN/ACKNOWLEDGED) alert per rule+source: update it instead of creating duplicates.
// A unique index in the database backs this up if two SOC tabs race each other.
async function createOrUpdateAlert(rule, source, count, first, last) {
  const find = () => sb.from("security_alerts").select("id,event_count,last_seen")
    .eq("alert_type", rule.type).eq("source", source).in("status", ["OPEN", "ACKNOWLEDGED"]).maybeSingle();
  let { data: existing, error } = await find();
  if (error) throw error;
  if (!existing) {
    const ins = await sb.from("security_alerts").insert({ alert_type: rule.type, severity: rule.severity, title: rule.title,
      description: rule.description, source, event_count: count, first_seen: first, last_seen: last, status: "OPEN" }).select().single();
    if (!ins.error) return { alert: ins.data, created: true };
    if (ins.error.code !== "23505") throw ins.error;
    ({ data: existing, error } = await find()); // lost the race: fall through to update
    if (error || !existing) throw error || new Error("alert not found");
  }
  if (existing.event_count !== count || existing.last_seen !== last) {
    const up = await sb.from("security_alerts").update({ event_count: count, last_seen: last }).eq("id", existing.id);
    if (up.error) throw up.error;
  }
  return { alert: existing, created: false };
}

// Run all rules for one source. Returns the alerts that were newly created.
async function analyseSource(source, refTime = new Date()) {
  const created = [];
  for (const rule of RULES) {
    const r = await evaluateRule(rule, source, refTime);
    if (r?.created) created.push({ ...r.alert, title: rule.title });
  }
  return created;
}
async function analyseEvent(ev) {
  return ev.event_type === "FAILED_LOGIN" ? analyseSource(ev.source, new Date(ev.created_at)) : [];
}
