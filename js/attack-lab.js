// CONTROLLED LAB: only talks to THIS project's own Supabase Auth (the Test Server's authentication backend).
// There is no URL field. A fixed number of attempts is made. Passwords are random strings, not guesses.
// FAILED_LOGIN rows are NOT inserted directly: the lab sends a real login request and calls the Test Server's
// own log_failed_login() function only after Supabase Auth really rejects the attempt.
const ATTEMPTS = 5, DELAY_MS = 1000, LAB_SOURCE = "ATTACK_LAB"; // events are clearly labelled as lab-generated
const labClient = (CONFIGURED && window.supabase) ? window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY,
  { auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false, storageKey: "cg-lab" } }) : null;

const logLine = t => { const el = document.getElementById("log"); el.textContent += t + "\n"; };
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function attemptFailedLogin(email) {
  const wrong = "wrong-" + crypto.randomUUID();
  const { error } = await labClient.auth.signInWithPassword({ email, password: wrong });
  if (!error) { await labClient.auth.signOut(); return "unexpected-success"; }
  if (error.status !== 400 && error.code !== "invalid_credentials") return "unavailable";
  const { error: e2 } = await labClient.rpc("log_failed_login", { p_email: email, p_source: LAB_SOURCE });
  return e2 ? "log-failed" : "rejected";
}
async function startBruteForceTest() {
  const email = document.getElementById("target-email").value.trim();
  const btn = document.getElementById("start");
  if (!/^\S+@\S+\.\S+$/.test(email)) return showMsg("msg", "Enter the Test Server login email.");
  btn.disabled = true; document.getElementById("log").textContent = ""; document.getElementById("msg").className = "msg";
  logLine("Test started");
  try {
    for (let i = 1; i <= ATTEMPTS; i++) {
      logLine(`Attempt ${i}: sending login request...`);
      const r = await attemptFailedLogin(email);
      if (r !== "rejected") { logLine(`  stopped (${r}). Auth may be rate-limiting; wait and retry, or use the manual procedure.`); return; }
      logLine("  rejected by Supabase Auth; FAILED_LOGIN recorded");
      if (i < ATTEMPTS) await sleep(DELAY_MS);
    }
    logLine("Test completed");
    showMsg("msg", "Done. Watch the SOC Dashboard (keep it open in another tab).", "ok");
  } catch (e) { console.error(e); showMsg("msg", "Test failed. Please try again."); }
  finally { btn.disabled = false; }
}
(async () => {
  if (!(await requireAnalyst())) return;
  if (!labClient) return showMsg("msg", "Supabase configuration required.");
  document.getElementById("start").addEventListener("click", startBruteForceTest);
})();
