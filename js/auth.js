// Shared helpers + SOC analyst authentication. Role is enforced by RLS; the checks here are for UX.
function esc(s) { return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
const badge = v => `<span class="badge ${esc(v).toLowerCase()}">${esc(v).replace(/_/g, " ")}</span>`;
const fmt = d => new Date(d).toLocaleString();
function toast(text, type = "info") {
  let box = document.getElementById("toasts");
  if (!box) { box = document.createElement("div"); box.id = "toasts"; document.body.appendChild(box); }
  const t = document.createElement("div"); t.className = "toast " + type; t.textContent = text; box.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}
function showMsg(id, text, type = "error") { const el = document.getElementById(id); if (el) { el.textContent = text; el.className = "msg show " + type; } }

async function isAnalyst(userId) {
  const { data, error } = await sb.from("profiles").select("role").eq("id", userId).maybeSingle();
  if (error) throw error;
  return data?.role === "soc_analyst";
}
// Call at the start of every protected page. Redirects to index.html if not an authenticated analyst.
async function requireAnalyst() {
  if (!sb) { location.replace("index.html"); return null; }
  try {
    const { data: { session } } = await sb.auth.getSession();
    if (!session) { location.replace("index.html"); return null; }
    if (!(await isAnalyst(session.user.id))) { await sb.auth.signOut(); location.replace("index.html"); return null; }
    document.body.classList.remove("locked");
    const who = document.getElementById("who"); if (who) who.textContent = session.user.email;
    sb.auth.onAuthStateChange(ev => { if (ev === "SIGNED_OUT") location.replace("index.html"); });
    return session.user;
  } catch (e) { console.error(e); location.replace("index.html"); return null; }
}
async function logout() {
  try { await sb.auth.signOut(); } catch (e) { console.error(e); }
  location.replace("index.html");
}
document.getElementById("logout")?.addEventListener("click", logout);

async function initLogin() {
  const form = document.getElementById("login-form"); if (!form) return;
  if (!sb) { showMsg("msg", "Supabase configuration required. Edit js/supabase.js (see README)."); document.getElementById("login-btn").disabled = true; return; }
  try { const { data: { session } } = await sb.auth.getSession(); if (session && await isAnalyst(session.user.id)) return location.replace("dashboard.html"); } catch (e) { /* show login */ }
  form.addEventListener("submit", async ev => {
    ev.preventDefault();
    const btn = document.getElementById("login-btn"); btn.disabled = true; btn.textContent = "AUTHENTICATING...";
    try {
      const { data, error } = await sb.auth.signInWithPassword({ email: document.getElementById("email").value.trim(), password: document.getElementById("password").value });
      if (error) return showMsg("msg", error.status === 400 ? "Invalid email or password." : "Unable to sign in right now. Please try again.");
      if (!(await isAnalyst(data.user.id))) { await sb.auth.signOut(); return showMsg("msg", "This account is not authorized for the SOC."); }
      location.href = "dashboard.html";
    } catch (e) { console.error(e); showMsg("msg", "Connection error. Please try again."); }
    finally { btn.disabled = false; btn.textContent = "SIGN IN"; }
  });
}
initLogin();
