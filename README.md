# CyberGuard SOC (V1)

## 1. What it is
A small Security Operations Center console (HTML, CSS, vanilla JS, Supabase). It reads the real events stored by the CyberGuard Test Server, detects failed-login patterns, raises alerts and tracks incidents.

## 2. Relationship with the Test Server
Both projects use the **same Supabase project**. The Test Server writes `security_events`; the SOC only reads them. The SOC adds `security_alerts` and `security_incidents` and a `role` column on `profiles`. Nothing from the Test Server is modified or deleted.

## 3. Architecture
CyberGuard Test Server
        ↓
Supabase security_events
        ↓
CyberGuard SOC
        ↓
Detection Engine
        ↓
Alerts
        ↓
Incidents

## 4. Create the SOC analyst account
Supabase -> Authentication -> Users -> Add user: `soc@cyberguard.test` with a password of your choice (not stored in code), "Auto Confirm User" ticked. Do this **before** step 5.

## 5. Run `supabase/soc_schema.sql`
SQL Editor -> paste -> Run. It is re-runnable, drops no tables and deletes no data. It adds `profiles.role` (`user` / `soc_analyst`), sets the analyst role, adds a read-only SELECT policy on `security_events` for analysts (the existing own-events policy is untouched), creates the alert/incident tables, and adds `security_events` to the Realtime publication. If you ever create the analyst later, run the script again.

## 6. Configure credentials
Put your Project URL and the anon/public (publishable) key in `js/supabase.js`. Never use a service-role or secret key.

## 7. Run locally
`python -m http.server 5500` in this folder, then open http://localhost:5500 (Python is only a static file server). The Test Server can run on another port.

## 8. Realtime
The dashboard subscribes to INSERTs on `security_events`. The script enables Realtime for that table; if the status stays "CONNECTING", check Database -> Replication/Publications. Realtime respects RLS, so only the analyst receives all events. Realtime is not used on other tables; Alerts and Incidents pages load on open (REFRESH button on Alerts).

## 9. Detection rules (`js/detection.js`)
- `BRUTE_FORCE` (HIGH): 5+ `FAILED_LOGIN` from one source within 5 minutes.
- `REPEATED_FAILED_LOGIN` (MEDIUM): 3+ from one source within 2 minutes.
Each new event triggers a query over real rows. Only one active (OPEN/ACKNOWLEDGED) alert exists per rule + source; further failures update `event_count`/`last_seen`. A unique database index enforces this. On page load a catch-up scan covers the last 5 minutes. Detection runs in the analyst's browser, so the dashboard must be open.

## 10. Alert workflow
OPEN -> ACKNOWLEDGED -> RESOLVED, plus CREATE INCIDENT. No delete.

## 11. Incident workflow
One incident per alert (unique index). NEW -> INVESTIGATING -> RESOLVED. No delete.

## 12. Attack Lab limitations
Fixed target: this project's own Supabase Auth; no URL input; 5 attempts with random wrong passwords. It does not insert rows into `security_events`. A browser cannot control the Test Server's page from another origin and no workaround is used, so the lab sends real login requests to Supabase Auth and, after each real rejection, calls the Test Server's `log_failed_login()` function. This replicates the Test Server's logging step rather than using its page. Events have source `ATTACK_LAB`. The manual procedure (5 wrong logins on the Test Server) is the authentic path and always works.

## 13. Demo
1. Open the SOC dashboard (signed in as analyst) in one tab, the Test Server in another.
2. Enter a wrong password 5 times on the Test Server (each browser has its own `browser-xxxxxxxx` source).
3. Watch events arrive; at 3 failures a MEDIUM alert appears, at 5 a HIGH "Possible Brute Force Attack".
4. Alerts page: ACKNOWLEDGE -> CREATE INCIDENT.
5. Incidents page: INVESTIGATE -> RESOLVE.
(Or use the Attack Lab.)

## 14. Security limitations
- Educational only. Role checks in JS are UX; real enforcement is RLS.
- Failed-login logging is open to anyone holding the anon key (Test Server design), so events can be spammed or attributed to a chosen email.
- Detection runs client-side and only while a dashboard is open; status transitions are enforced in the UI, not the database.
- Analyst accounts can still insert their own Test Server style events (existing policy), but cannot update or delete any event.
- Verified in the configured local lab: SOC login, realtime events, repeated-login/brute-force alerts, alert workflow, incident workflow, and Attack Lab were tested successfully.

## 15. Phase 2 containment
Phase 2 adds real source-level containment. The Test Server's login request is handled by the `secure-login` Supabase Edge Function before Supabase Auth is called. The browser sends a persistent per-browser source ID; this is a lab device/source identifier, not a claim that the value is a public IP.

After a HIGH `BRUTE_FORCE` incident is moved to `INVESTIGATING`, the analyst can click **BLOCK SOURCE · 15 MIN**. This creates/updates a temporary block in `security_source_blocks`. The login Edge Function checks that block before authentication. A blocked source receives HTTP 423 and a real `BLOCKED_LOGIN` event is recorded. The user account is never disabled, so another device can still authenticate with the same email/password.

`browser-98fabb55` is inserted into `security_trusted_sources` and can never be blocked. `ATTACK_LAB` remains a labelled lab source and is not intended to be used as the containment target.

### Edge Function deployment
Deploy `supabase/functions/secure-login/index.js` as the function `secure-login`. In the function's environment/secrets, configure `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY`. The service-role key is server-side only and must never be placed in browser JS or committed to Git. The browser continues to use only the publishable/anon key.

Before using the new login flow, run `supabase/phase2_blocking.sql` in the project's SQL Editor. Then deploy the Edge Function. Test with two different browsers/devices: trigger 5 failed logins from a non-trusted source, create/investigate the brute-force incident, block the source, verify that source is rejected while another device can still log in with the same account, and verify the block expires after 15 minutes.
