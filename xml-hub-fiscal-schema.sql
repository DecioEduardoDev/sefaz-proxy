-- =====================================================================
-- XML Hub Fiscal — esquema completo (Supabase)
-- Executar no SQL Editor do projeto cqbzmzowjwslcyamiuyi
-- =====================================================================

-- ---------- Extensões / tipos ----------
create extension if not exists "pgcrypto";

do $$ begin
  create type public.app_role as enum ('admin', 'gestor', 'contador', 'usuario');
exception when duplicate_object then null; end $$;

-- ---------- updated_at ----------
create or replace function public.update_updated_at_column()
returns trigger language plpgsql set search_path = public as $$
begin new.updated_at = now(); return new; end; $$;

-- ---------- companies ----------
create table if not exists public.companies (
  id uuid primary key default gen_random_uuid(),
  cnpj varchar(14) not null unique,
  razao_social varchar(250) not null,
  nome_fantasia varchar(250),
  inscricao_estadual varchar(30),
  email varchar(200),
  telefone varchar(30),
  status boolean not null default true,
  certificado_path text,
  certificado_senha text,
  certificado_validade date,
  certificado_status varchar(20) not null default 'ausente',
  ultimo_nsu varchar(20) not null default '000000000000000',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

grant select, insert, update, delete on public.companies to authenticated;
grant all on public.companies to service_role;
alter table public.companies enable row level security;

-- ---------- profiles ----------
create table if not exists public.profiles (
  id uuid primary key,
  company_id uuid references public.companies(id) on delete set null,
  name varchar(200) not null default '',
  email varchar(200) not null default '',
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

grant select, insert, update, delete on public.profiles to authenticated;
grant all on public.profiles to service_role;
alter table public.profiles enable row level security;

-- ---------- user_roles ----------
create table if not exists public.user_roles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  role public.app_role not null,
  created_at timestamptz not null default now(),
  unique (user_id, role)
);

grant select on public.user_roles to authenticated;
grant all on public.user_roles to service_role;
alter table public.user_roles enable row level security;

-- ---------- funções de segurança ----------
create or replace function public.has_role(_user_id uuid, _role public.app_role)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.user_roles where user_id = _user_id and role = _role);
$$;

create or replace function public.current_company_id()
returns uuid language sql stable security definer set search_path = public as $$
  select company_id from public.profiles where id = auth.uid();
$$;

-- ---------- invoices ----------
create table if not exists public.invoices (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  chave_acesso varchar(44) not null,
  numero_nfe varchar(20),
  serie varchar(10),
  emitente_cnpj varchar(14),
  emitente_nome varchar(250),
  valor_total numeric(15,2),
  data_emissao timestamptz,
  status varchar(30) not null default 'autorizada',
  nsu varchar(20),
  storage_path text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (company_id, chave_acesso)
);

create index if not exists invoices_company_data_idx on public.invoices (company_id, data_emissao desc);
create index if not exists invoices_emitente_idx on public.invoices (company_id, emitente_cnpj);

grant select, insert, update, delete on public.invoices to authenticated;
grant all on public.invoices to service_role;
alter table public.invoices enable row level security;

-- ---------- audit_logs ----------
create table if not exists public.audit_logs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid,
  company_id uuid references public.companies(id) on delete cascade,
  action varchar(50) not null,
  invoice_id uuid references public.invoices(id) on delete set null,
  file_name text,
  ip varchar(60),
  created_at timestamptz not null default now()
);

create index if not exists audit_logs_company_idx on public.audit_logs (company_id, created_at desc);

grant select, insert on public.audit_logs to authenticated;
grant all on public.audit_logs to service_role;
alter table public.audit_logs enable row level security;

-- ---------- triggers updated_at ----------
drop trigger if exists companies_updated_at on public.companies;
create trigger companies_updated_at before update on public.companies
  for each row execute function public.update_updated_at_column();
drop trigger if exists profiles_updated_at on public.profiles;
create trigger profiles_updated_at before update on public.profiles
  for each row execute function public.update_updated_at_column();
drop trigger if exists invoices_updated_at on public.invoices;
create trigger invoices_updated_at before update on public.invoices
  for each row execute function public.update_updated_at_column();

-- ---------- criação automática de profile ----------
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, name, email)
  values (new.id, coalesce(new.raw_user_meta_data->>'name', ''), coalesce(new.email, ''))
  on conflict (id) do nothing;
  insert into public.user_roles (user_id, role) values (new.id, 'usuario')
  on conflict do nothing;
  return new;
end; $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- =====================================================================
-- POLÍTICAS (RLS) — isolamento total por empresa
-- =====================================================================

-- companies
drop policy if exists "companies_select" on public.companies;
create policy "companies_select" on public.companies for select to authenticated
  using (id = public.current_company_id() or public.has_role(auth.uid(), 'admin'));

drop policy if exists "companies_insert_admin" on public.companies;
create policy "companies_insert_admin" on public.companies for insert to authenticated
  with check (public.has_role(auth.uid(), 'admin'));

drop policy if exists "companies_update" on public.companies;
create policy "companies_update" on public.companies for update to authenticated
  using (public.has_role(auth.uid(), 'admin')
     or (id = public.current_company_id() and public.has_role(auth.uid(), 'gestor')))
  with check (public.has_role(auth.uid(), 'admin')
     or (id = public.current_company_id() and public.has_role(auth.uid(), 'gestor')));

drop policy if exists "companies_delete_admin" on public.companies;
create policy "companies_delete_admin" on public.companies for delete to authenticated
  using (public.has_role(auth.uid(), 'admin'));

-- profiles
drop policy if exists "profiles_select" on public.profiles;
create policy "profiles_select" on public.profiles for select to authenticated
  using (id = auth.uid()
      or company_id = public.current_company_id()
      or public.has_role(auth.uid(), 'admin'));

drop policy if exists "profiles_update_self" on public.profiles;
create policy "profiles_update_self" on public.profiles for update to authenticated
  using (id = auth.uid() or public.has_role(auth.uid(), 'admin'))
  with check (id = auth.uid() or public.has_role(auth.uid(), 'admin'));

drop policy if exists "profiles_insert_admin" on public.profiles;
create policy "profiles_insert_admin" on public.profiles for insert to authenticated
  with check (public.has_role(auth.uid(), 'admin'));

-- user_roles
drop policy if exists "user_roles_select" on public.user_roles;
create policy "user_roles_select" on public.user_roles for select to authenticated
  using (user_id = auth.uid() or public.has_role(auth.uid(), 'admin'));

-- invoices
drop policy if exists "invoices_select" on public.invoices;
create policy "invoices_select" on public.invoices for select to authenticated
  using (company_id = public.current_company_id() or public.has_role(auth.uid(), 'admin'));

drop policy if exists "invoices_insert" on public.invoices;
create policy "invoices_insert" on public.invoices for insert to authenticated
  with check (company_id = public.current_company_id() or public.has_role(auth.uid(), 'admin'));

drop policy if exists "invoices_update" on public.invoices;
create policy "invoices_update" on public.invoices for update to authenticated
  using (company_id = public.current_company_id() or public.has_role(auth.uid(), 'admin'))
  with check (company_id = public.current_company_id() or public.has_role(auth.uid(), 'admin'));

-- audit_logs
drop policy if exists "audit_select" on public.audit_logs;
create policy "audit_select" on public.audit_logs for select to authenticated
  using (company_id = public.current_company_id() or public.has_role(auth.uid(), 'admin'));

drop policy if exists "audit_insert" on public.audit_logs;
create policy "audit_insert" on public.audit_logs for insert to authenticated
  with check (user_id = auth.uid());

-- =====================================================================
-- STORAGE
-- =====================================================================
insert into storage.buckets (id, name, public) values ('xml-nfe', 'xml-nfe', false)
  on conflict (id) do nothing;
insert into storage.buckets (id, name, public) values ('certificados', 'certificados', false)
  on conflict (id) do nothing;

-- XMLs: caminho = {company_id}/{ano}/{mes}/{chave}.xml
drop policy if exists "xml_select" on storage.objects;
create policy "xml_select" on storage.objects for select to authenticated
  using (bucket_id = 'xml-nfe'
     and ((storage.foldername(name))[1] = public.current_company_id()::text
          or public.has_role(auth.uid(), 'admin')));

drop policy if exists "xml_insert" on storage.objects;
create policy "xml_insert" on storage.objects for insert to authenticated
  with check (bucket_id = 'xml-nfe'
     and ((storage.foldername(name))[1] = public.current_company_id()::text
          or public.has_role(auth.uid(), 'admin')));

-- Certificados: gravação restrita; leitura apenas service_role (integração SEFAZ)
drop policy if exists "cert_insert" on storage.objects;
create policy "cert_insert" on storage.objects for insert to authenticated
  with check (bucket_id = 'certificados'
     and (storage.foldername(name))[1] = public.current_company_id()::text
     and (public.has_role(auth.uid(), 'gestor') or public.has_role(auth.uid(), 'admin')));

drop policy if exists "cert_update" on storage.objects;
create policy "cert_update" on storage.objects for update to authenticated
  using (bucket_id = 'certificados'
     and (storage.foldername(name))[1] = public.current_company_id()::text
     and (public.has_role(auth.uid(), 'gestor') or public.has_role(auth.uid(), 'admin')));

-- =====================================================================
-- Primeiro administrador (troque o e-mail depois de criar o usuário):
-- insert into public.user_roles (user_id, role)
-- select id, 'admin' from auth.users where email = 'voce@empresa.com'
-- on conflict do nothing;
-- =====================================================================
