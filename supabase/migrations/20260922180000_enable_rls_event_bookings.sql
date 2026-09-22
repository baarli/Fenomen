-- Fenomen Folk (sjrxmjjqpxrmshcwwkzh): slå på RLS for public.event_bookings
-- Forberedt av Jarvis 2026-09-22. IKKE kjørt mot prod.
--
-- event_bookings er koblingstabellen events <-> bookings (honorar, kundekontakt ligger i bookings/events).
-- Modell (speiler policyene på bookings/events):
--   * Lese: admin, management, talent på bookingen, eller den som opprettet / er talent på eventet.
--   * Skrive (insert/update/delete): kun admin og management.
--   * anon: ingen tilgang i det hele tatt.

begin;

alter table public.event_bookings enable row level security;

revoke all on public.event_bookings from anon;
revoke truncate, trigger, references on public.event_bookings from authenticated;

drop policy if exists "Relevant users can view event bookings" on public.event_bookings;
create policy "Relevant users can view event bookings" on public.event_bookings
  for select to authenticated
  using (
    (select public.is_admin())
    or (select public.is_management())
    or public.is_talent_of_booking(booking_id)
    or exists (
      select 1 from public.events e
      where e.id = event_id
        and (e.created_by = (select auth.uid()) or e.talent_id = (select auth.uid()))
    )
  );

drop policy if exists "Management can insert event bookings" on public.event_bookings;
create policy "Management can insert event bookings" on public.event_bookings
  for insert to authenticated
  with check ((select public.is_admin()) or (select public.is_management()));

drop policy if exists "Management can update event bookings" on public.event_bookings;
create policy "Management can update event bookings" on public.event_bookings
  for update to authenticated
  using ((select public.is_admin()) or (select public.is_management()))
  with check ((select public.is_admin()) or (select public.is_management()));

drop policy if exists "Management can delete event bookings" on public.event_bookings;
create policy "Management can delete event bookings" on public.event_bookings
  for delete to authenticated
  using ((select public.is_admin()) or (select public.is_management()));

commit;

-- Verifisering etterpå (skal gi 0 rader):
-- select relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
-- where n.nspname = 'public' and c.relkind = 'r' and not c.relrowsecurity;
