-- Prompt Library CONSCOOP: permesso di MODIFICA dei prompt.
-- Da eseguire una volta in Supabase (SQL Editor). Prima controlla le policy già presenti:
--   select policyname, cmd, qual, with_check from pg_policies where tablename = 'prompts';
-- e allinea le condizioni qui sotto a quelle della policy di INSERT, se usa nomi diversi.
--
-- Regola: chi può aggiungere prompt in una pagina può anche modificarli.
--   - amministratore (app_metadata.ruolo = 'admin'): tutti i prompt;
--   - account di reparto (app_metadata.reparto): i prompt del proprio reparto e quelli "Generali".
-- Chi non è amministratore non può spostare un prompt nel reparto di altri né cambiarne lo stato.

alter table public.prompts enable row level security;

drop policy if exists "modifica prompt" on public.prompts;
create policy "modifica prompt" on public.prompts
  for update to authenticated
  using (
    (auth.jwt() -> 'app_metadata' ->> 'ruolo') = 'admin'
    or reparto = 'Generali'
    or reparto = (auth.jwt() -> 'app_metadata' ->> 'reparto')
  )
  with check (
    (auth.jwt() -> 'app_metadata' ->> 'ruolo') = 'admin'
    or reparto = 'Generali'
    or reparto = (auth.jwt() -> 'app_metadata' ->> 'reparto')
  );

-- Campi che la modifica non deve mai toccare (chi l'ha creato, quando) e stato riservato all'amministratore.
create or replace function public.prompts_proteggi_modifica()
returns trigger language plpgsql as $$
begin
  new.id := old.id;
  new.created_at := old.created_at;
  new.creato_da := old.creato_da;
  if coalesce(auth.jwt() -> 'app_metadata' ->> 'ruolo', '') <> 'admin' then
    new.stato := old.stato;
  end if;
  return new;
end;
$$;

drop trigger if exists prompts_proteggi_modifica on public.prompts;
create trigger prompts_proteggi_modifica
  before update on public.prompts
  for each row execute function public.prompts_proteggi_modifica();
