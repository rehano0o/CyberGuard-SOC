-- ============================================================
-- CyberGuard SOC - Phase 3
-- Device History + Progressive Brute-Force Containment
--
-- IMPORTANT:
-- This migration is ADDITIVE.
--
-- It does NOT replace or modify:
--   log_failed_login()
--   block_security_source()
--   is_source_blocked()
--   existing RLS policies
--   existing dashboard detection
--   existing Attack Lab
--
-- Run AFTER:
--   soc_schema.sql
--   phase2_blocking.sql
--
-- Safe to run more than once.
-- ============================================================


-- ============================================================
-- 1. Permanent block history
-- ============================================================

create table if not exists public.security_source_block_history (
  id uuid primary key default gen_random_uuid(),

  source text not null,

  blocked_until timestamptz not null,

  blocked_by uuid
    references auth.users(id)
    on delete set null,

  reason text not null,

  created_at timestamptz not null default now(),

  unblocked_at timestamptz
);

create index if not exists idx_block_history_source
on public.security_source_block_history(source);

create index if not exists idx_block_history_created
on public.security_source_block_history(created_at desc);


-- ============================================================
-- RLS for block history
-- SOC analysts can read it.
-- Normal users cannot.
-- ============================================================

alter table public.security_source_block_history
enable row level security;

revoke all
on public.security_source_block_history
from anon, authenticated;

grant select
on public.security_source_block_history
to authenticated;

drop policy if exists "soc block history select"
on public.security_source_block_history;

create policy "soc block history select"
on public.security_source_block_history
for select
to authenticated
using (public.is_soc_analyst());


-- ============================================================
-- 2. Automatic containment function
--
-- This is DIFFERENT from the existing
-- block_security_source().
--
-- Existing manual SOC function remains untouched.
--
-- This function is called internally by the Phase 3 trigger.
-- ============================================================

create or replace function public.auto_block_security_source(
  p_source text,
  p_minutes integer default 15
)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  v_source text;
  v_until timestamptz;
begin

  v_source := left(
    coalesce(
      nullif(trim(p_source), ''),
      'UNKNOWN'
    ),
    64
  );

  -- Never automatically block explicitly trusted sources.
  if exists (
    select 1
    from public.security_trusted_sources
    where source = v_source
  ) then
    return false;
  end if;

  if p_minutes < 1 or p_minutes > 60 then
    raise exception 'Block duration must be 1-60 minutes';
  end if;

  v_until :=
    now() + make_interval(mins => p_minutes);


  -- Maintain the existing active-block table.
  insert into public.security_source_blocks (
    source,
    blocked_until,
    blocked_by,
    reason
  )
  values (
    v_source,
    v_until,
    null,
    'Automatic 10-failed-login containment'
  )
  on conflict (source)
  do update
  set
    blocked_until = excluded.blocked_until,
    blocked_by = null,
    reason = excluded.reason,
    created_at = now();


  -- Keep an append-only historical record.
  insert into public.security_source_block_history (
    source,
    blocked_until,
    blocked_by,
    reason
  )
  values (
    v_source,
    v_until,
    null,
    'Automatic 10-failed-login containment'
  );

  return true;

end;
$$;


-- Nobody can directly call the automatic containment function.
-- It is intended to be invoked internally by the trigger.

revoke all
on function public.auto_block_security_source(text, integer)
from public, anon, authenticated;

grant execute
on function public.auto_block_security_source(text, integer)
to service_role;


-- ============================================================
-- 3. Progressive failed-login processor
--
-- Thresholds:
--
-- 3 failures within 2 minutes
--     -> MEDIUM
--
-- 5 failures within 5 minutes
--     -> HIGH
--
-- 10 failures within 15 minutes
--     -> CRITICAL
--     -> automatic 15-minute block
--     -> CRITICAL alert
--     -> CRITICAL incident
--
-- This runs automatically after a FAILED_LOGIN event is inserted.
-- It does NOT depend on the SOC dashboard.
-- ============================================================

create or replace function public.process_failed_login_security()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_count_2m integer;
  v_count_5m integer;
  v_count_15m integer;

  v_alert_id uuid;
begin

  -- Only process failed-login events.
  if NEW.event_type <> 'FAILED_LOGIN' then
    return NEW;
  end if;


  -- ==========================================================
  -- Count recent failures for this source.
  -- ==========================================================

  select count(*)
  into v_count_2m
  from public.security_events
  where event_type = 'FAILED_LOGIN'
    and source = NEW.source
    and created_at >= NEW.created_at - interval '2 minutes';


  select count(*)
  into v_count_5m
  from public.security_events
  where event_type = 'FAILED_LOGIN'
    and source = NEW.source
    and created_at >= NEW.created_at - interval '5 minutes';


  select count(*)
  into v_count_15m
  from public.security_events
  where event_type = 'FAILED_LOGIN'
    and source = NEW.source
    and created_at >= NEW.created_at - interval '15 minutes';


  -- ==========================================================
  -- LEVEL 3: CRITICAL
  -- 10+ failures within 15 minutes
  -- ==========================================================

  if v_count_15m >= 10 then

    -- Mark this event CRITICAL.
    update public.security_events
    set
      severity = 'CRITICAL',
      description =
        'Critical: 10 or more failed login attempts from this source within 15 minutes.'
    where id = NEW.id;


    -- Create or update the CRITICAL alert.
    insert into public.security_alerts (
      alert_type,
      severity,
      title,
      description,
      source,
      event_count,
      first_seen,
      last_seen,
      status
    )
    select
      'AUTOMATIC_DEVICE_CONTAINMENT',
      'CRITICAL',
      'Critical Brute Force - Device Automatically Blocked',
      '10 or more failed login attempts detected from the same source within 15 minutes. The source was automatically blocked for 15 minutes.',
      NEW.source,
      count(*),
      min(created_at),
      max(created_at),
      'OPEN'
    from public.security_events
    where event_type = 'FAILED_LOGIN'
      and source = NEW.source
      and created_at >= NEW.created_at - interval '15 minutes'

    on conflict (alert_type, source)
    where status in ('OPEN', 'ACKNOWLEDGED')
    do update
    set
      severity = 'CRITICAL',
      event_count = excluded.event_count,
      last_seen = excluded.last_seen;


    -- Find the active alert.
    select id
    into v_alert_id
    from public.security_alerts
    where alert_type = 'AUTOMATIC_DEVICE_CONTAINMENT'
      and source = NEW.source
      and status in ('OPEN', 'ACKNOWLEDGED')
    order by created_at desc
    limit 1;


    -- Create one incident for the alert.
    if v_alert_id is not null then

      insert into public.security_incidents (
        alert_id,
        title,
        severity,
        description,
        status
      )
      values (
        v_alert_id,
        'Automatic Device Containment - ' || NEW.source,
        'CRITICAL',
        'The source reached 10 failed login attempts within 15 minutes and was automatically blocked for 15 minutes.',
        'NEW'
      )

      on conflict (alert_id)
      do update
      set
        severity = 'CRITICAL',
        updated_at = now();

    end if;


    -- Automatically block the source.
    perform public.auto_block_security_source(
      NEW.source,
      15
    );


  -- ==========================================================
  -- LEVEL 2: HIGH
  -- 5+ failures within 5 minutes
  -- ==========================================================

  elsif v_count_5m >= 5 then

    update public.security_events
    set
      severity = 'HIGH',
      description =
        'High: 5 or more failed login attempts from this source within 5 minutes.'
    where id = NEW.id;


  -- ==========================================================
  -- LEVEL 1: MEDIUM
  -- 3+ failures within 2 minutes
  -- ==========================================================

  elsif v_count_2m >= 3 then

    update public.security_events
    set
      severity = 'MEDIUM',
      description =
        'Multiple failed login attempts from this source within 2 minutes.'
    where id = NEW.id;

  end if;


  return NEW;

end;
$$;


-- Prevent direct execution by normal clients.

revoke all
on function public.process_failed_login_security()
from public, anon, authenticated;


-- ============================================================
-- 4. Attach the processor to security_events
--
-- There were NO existing triggers on this table when checked,
-- so this creates the first one.
-- ============================================================

drop trigger if exists trg_process_failed_login_security
on public.security_events;

create trigger trg_process_failed_login_security
after insert
on public.security_events
for each row
execute function public.process_failed_login_security();


-- ============================================================
-- 5. Device/source summary view
--
-- Device History uses security_events as the source of truth.
-- We deliberately DO NOT duplicate every event into another
-- history table.
-- ============================================================

create or replace view public.security_device_summary
with (security_invoker = true)
as
select
  source,

  count(*) as total_events,

  count(*) filter (
    where event_type = 'LOGIN_SUCCESS'
  ) as successful_logins,

  count(*) filter (
    where event_type = 'FAILED_LOGIN'
  ) as failed_logins,

  count(*) filter (
    where event_type = 'LOGOUT'
  ) as logouts,

  count(*) filter (
    where event_type = 'BLOCKED_LOGIN'
  ) as blocked_logins,

  count(*) filter (
    where severity = 'CRITICAL'
  ) as critical_events,

  max(created_at) as last_seen

from public.security_events

group by source;


grant select
on public.security_device_summary
to authenticated;


-- ============================================================
-- 6. Finished
-- ============================================================

-- Phase 3 adds:
--
-- security_source_block_history
-- auto_block_security_source()
-- process_failed_login_security()
-- trg_process_failed_login_security
-- security_device_summary
--
-- Existing Phase 1/Phase 2 functions remain untouched.
-- ============================================================