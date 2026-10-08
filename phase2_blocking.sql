-- CyberGuard Phase 2: source/device containment.
-- Run AFTER soc_schema.sql in the SAME Supabase project.
-- This does NOT disable user accounts. It blocks only a source/device identifier.

alter table public.security_events drop constraint if exists security_events_event_type_check;
alter table public.security_events add constraint security_events_event_type_check
  check (event_type in ('LOGIN_SUCCESS','FAILED_LOGIN','LOGOUT','TEST_REQUEST','BLOCKED_LOGIN'));

create table if not exists public.security_source_blocks (
  source text primary key,
  blocked_until timestamptz not null,
  blocked_by uuid references auth.users(id) on delete set null,
  reason text not null default 'Brute-force containment',
  created_at timestamptz not null default now()
);
create index if not exists idx_source_blocks_until on public.security_source_blocks(blocked_until);

alter table public.security_source_blocks enable row level security;
revoke all on public.security_source_blocks from anon, authenticated;
grant select, insert, update on public.security_source_blocks to authenticated;

drop policy if exists "soc source blocks select" on public.security_source_blocks;
drop policy if exists "soc source blocks insert" on public.security_source_blocks;
drop policy if exists "soc source blocks update" on public.security_source_blocks;
create policy "soc source blocks select" on public.security_source_blocks for select to authenticated
  using (public.is_soc_analyst());
create policy "soc source blocks insert" on public.security_source_blocks for insert to authenticated
  with check (public.is_soc_analyst());
create policy "soc source blocks update" on public.security_source_blocks for update to authenticated
  using (public.is_soc_analyst()) with check (public.is_soc_analyst());

-- Explicitly trusted sources. These can generate alerts but can never be blocked.
create table if not exists public.security_trusted_sources (
  source text primary key,
  reason text not null,
  created_at timestamptz not null default now()
);
alter table public.security_trusted_sources enable row level security;
revoke all on public.security_trusted_sources from anon, authenticated;
grant select on public.security_trusted_sources to authenticated;
drop policy if exists "soc trusted sources select" on public.security_trusted_sources;
create policy "soc trusted sources select" on public.security_trusted_sources for select to authenticated
  using (public.is_soc_analyst());
insert into public.security_trusted_sources(source, reason)
values ('browser-98fabb55', 'Protected demo/trusted source')
on conflict (source) do update set reason = excluded.reason;

-- SOC action: create/update a 15-minute block. Trusted sources are rejected.
create or replace function public.block_security_source(p_source text, p_minutes integer default 15)
returns boolean
language plpgsql security definer set search_path = public
as $$
declare v_source text := left(coalesce(nullif(trim(p_source),''),'UNKNOWN'),64);
begin
  if not public.is_soc_analyst() then raise exception 'SOC analyst required'; end if;
  if exists (select 1 from public.security_trusted_sources where source = v_source) then
    return false;
  end if;
  if p_minutes < 1 or p_minutes > 60 then raise exception 'Block duration must be 1-60 minutes'; end if;
  insert into public.security_source_blocks(source, blocked_until, blocked_by, reason)
  values (v_source, now() + make_interval(mins => p_minutes), auth.uid(), 'Brute-force containment')
  on conflict (source) do update set blocked_until = excluded.blocked_until, blocked_by = excluded.blocked_by,
    reason = excluded.reason, created_at = now();
  return true;
end $$;
revoke all on function public.block_security_source(text, integer) from public, anon;
grant execute on function public.block_security_source(text, integer) to authenticated;

-- Cleanup helper used by the server-side login function; expired rows are harmless and removed lazily.
create or replace function public.is_source_blocked(p_source text)
returns timestamptz
language plpgsql security definer set search_path = public
as $$
declare v_until timestamptz;
begin
  select blocked_until into v_until from public.security_source_blocks where source = left(coalesce(nullif(trim(p_source),''),'UNKNOWN'),64);
  if v_until is null then return null; end if;
  if v_until <= now() then
    delete from public.security_source_blocks where source = left(coalesce(nullif(trim(p_source),''),'UNKNOWN'),64);
    return null;
  end if;
  return v_until;
end $$;
revoke all on function public.is_source_blocked(text) from public, anon, authenticated;
grant execute on function public.is_source_blocked(text) to service_role;
-- Only the Edge Function's service role should call this function.
