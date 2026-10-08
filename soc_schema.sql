-- CyberGuard SOC migration. Safe to run on the existing Test Server database (no drops of tables/data; re-runnable).
-- Create the analyst user (soc@cyberguard.test) in Authentication -> Users BEFORE running this.

-- 1. Roles on profiles
alter table public.profiles add column if not exists role text not null default 'user';
do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'profiles_role_check') then
    alter table public.profiles add constraint profiles_role_check check (role in ('user','soc_analyst'));
  end if;
end $$;
insert into public.profiles(id, email, display_name)
  select id, email, 'SOC Analyst' from auth.users where email = 'soc@cyberguard.test' on conflict (id) do nothing;
update public.profiles set role = 'soc_analyst' where email = 'soc@cyberguard.test';
-- Existing privileges already stop users from updating profiles, so nobody can promote themselves.

create or replace function public.is_soc_analyst() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'soc_analyst')
$$;
revoke all on function public.is_soc_analyst() from public, anon;
grant execute on function public.is_soc_analyst() to authenticated;

-- 2. Analyst can READ all events. The existing "own events" policy is untouched (policies are OR-ed).
drop policy if exists "soc read all events" on public.security_events;
create policy "soc read all events" on public.security_events for select to authenticated using (public.is_soc_analyst());

-- 3. Realtime for security_events
do $$ begin
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'security_events') then
    alter publication supabase_realtime add table public.security_events;
  end if;
end $$;

-- 4. Alerts
create table if not exists public.security_alerts (
  id uuid primary key default gen_random_uuid(),
  alert_type text not null,
  severity text not null check (severity in ('LOW','MEDIUM','HIGH','CRITICAL')),
  title text not null,
  description text,
  source text not null,
  event_count integer not null default 1,
  first_seen timestamptz not null,
  last_seen timestamptz not null,
  status text not null default 'OPEN' check (status in ('OPEN','ACKNOWLEDGED','RESOLVED')),
  created_at timestamptz not null default now()
);
create index if not exists idx_alerts_status on public.security_alerts(status);
create index if not exists idx_alerts_created on public.security_alerts(created_at desc);
create index if not exists idx_alerts_source on public.security_alerts(source);
-- At most one ACTIVE alert per rule + source (duplicate control)
create unique index if not exists uq_active_alert on public.security_alerts(alert_type, source) where status in ('OPEN','ACKNOWLEDGED');

-- 5. Incidents
create table if not exists public.security_incidents (
  id uuid primary key default gen_random_uuid(),
  alert_id uuid not null references public.security_alerts(id),
  title text not null,
  severity text not null check (severity in ('LOW','MEDIUM','HIGH','CRITICAL')),
  description text,
  status text not null default 'NEW' check (status in ('NEW','INVESTIGATING','RESOLVED')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create unique index if not exists uq_incident_alert on public.security_incidents(alert_id); -- one incident per alert
create index if not exists idx_incidents_status on public.security_incidents(status);
create index if not exists idx_incidents_created on public.security_incidents(created_at desc);

-- 6. RLS + privileges (analyst only; no DELETE anywhere; column-level UPDATE)
alter table public.security_alerts enable row level security;
alter table public.security_incidents enable row level security;
revoke all on public.security_alerts, public.security_incidents from anon, authenticated;
grant select, insert on public.security_alerts, public.security_incidents to authenticated;
grant update (status, event_count, last_seen) on public.security_alerts to authenticated;
grant update (status, updated_at) on public.security_incidents to authenticated;

drop policy if exists "soc alerts select" on public.security_alerts;
drop policy if exists "soc alerts insert" on public.security_alerts;
drop policy if exists "soc alerts update" on public.security_alerts;
create policy "soc alerts select" on public.security_alerts for select to authenticated using (public.is_soc_analyst());
create policy "soc alerts insert" on public.security_alerts for insert to authenticated with check (public.is_soc_analyst());
create policy "soc alerts update" on public.security_alerts for update to authenticated using (public.is_soc_analyst()) with check (public.is_soc_analyst());
drop policy if exists "soc incidents select" on public.security_incidents;
drop policy if exists "soc incidents insert" on public.security_incidents;
drop policy if exists "soc incidents update" on public.security_incidents;
create policy "soc incidents select" on public.security_incidents for select to authenticated using (public.is_soc_analyst());
create policy "soc incidents insert" on public.security_incidents for insert to authenticated with check (public.is_soc_analyst());
create policy "soc incidents update" on public.security_incidents for update to authenticated using (public.is_soc_analyst()) with check (public.is_soc_analyst());
