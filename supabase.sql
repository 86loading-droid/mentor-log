-- 멘토-멘티 학습 점검(동행 기록) — Supabase 스키마
-- Supabase 대시보드 > SQL Editor 에 전체를 붙여넣고 Run 하십시오. 여러 번 실행해도 안전합니다.
-- 설계 원칙: 모든 테이블은 RLS 로 직접 접근을 막고, PIN 을 확인하는 함수(RPC)로만 읽고 씁니다.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.mm_settings (
  id int primary key default 1 check (id = 1),
  admin_pin_hash text not null,
  created_at timestamptz default now()
);

create table if not exists public.mm_teams (
  id uuid primary key default gen_random_uuid(),
  code text unique not null,
  pin_hash text not null,
  name text not null,
  topic text default '',
  mentor text default '',
  mentee text default '',
  goals jsonb default '[]'::jsonb,
  example_set text default 'general',
  created_at timestamptz default now()
);
alter table public.mm_teams add column if not exists example_set text default 'general';

create table if not exists public.mm_sessions (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references public.mm_teams(id) on delete cascade,
  session_date date not null,
  minutes int default 0,
  mode text default '대면',
  place text default '',
  topic text default '',
  content text default '',
  output_link text default '',
  difficulty text default '',
  next_plan text default '',
  photos jsonb not null default '[]'::jsonb,
  self_rating jsonb default '{}'::jsonb,
  mentor_rating jsonb default '{}'::jsonb,
  gas jsonb default '{}'::jsonb,
  unit text default '',
  narrative jsonb default '{}'::jsonb,
  author text default '',
  created_at timestamptz default now()
);

alter table public.mm_sessions add column if not exists unit text default '';
alter table public.mm_sessions add column if not exists narrative jsonb default '{}'::jsonb;

create table if not exists public.mm_comments (
  id uuid primary key default gen_random_uuid(),
  session_id uuid not null references public.mm_sessions(id) on delete cascade,
  team_id uuid not null references public.mm_teams(id) on delete cascade,
  role text not null check (role in ('admin','mentor','mentee')),
  author text default '',
  body text not null,
  created_at timestamptz default now()
);

create table if not exists public.mm_notices (
  id uuid primary key default gen_random_uuid(),
  team_id uuid references public.mm_teams(id) on delete cascade,
  body text not null,
  created_at timestamptz default now()
);

create table if not exists public.mm_attempts (
  key text primary key,
  fails int default 0,
  locked_until timestamptz
);

alter table public.mm_settings enable row level security;
alter table public.mm_teams    enable row level security;
alter table public.mm_sessions enable row level security;
alter table public.mm_comments enable row level security;
alter table public.mm_notices  enable row level security;
alter table public.mm_attempts enable row level security;

-- ───── 내부 도우미 (외부 호출 불가) ─────
-- 오류를 raise 하면 실패 횟수 기록도 롤백되므로, 인증 실패는 {error} 를 반환하는 방식으로 처리합니다.
-- 같은 대상(교수자/팀)에 PIN 을 5회 연속 틀리면 10분간 잠깁니다.
create or replace function public._mm_check(p_key text, p_ok boolean)
returns text language plpgsql security definer set search_path = public as $$
declare r mm_attempts;
begin
  select * into r from mm_attempts where key = p_key;
  if r.locked_until is not null and r.locked_until > now() then return 'LOCKED'; end if;
  if p_ok then delete from mm_attempts where key = p_key; return 'OK'; end if;
  insert into mm_attempts(key, fails) values (p_key, 1)
    on conflict (key) do update set fails = mm_attempts.fails + 1, locked_until = null;
  update mm_attempts set fails = 0, locked_until = now() + interval '10 minutes'
    where key = p_key and fails >= 5;
  return 'BAD_PIN';
end $$;

create or replace function public._mm_admin(p_pin text)
returns text language plpgsql security definer set search_path = public, extensions as $$
declare h text;
begin
  select admin_pin_hash into h from mm_settings where id = 1;
  if h is null then return 'NOT_INITIALIZED'; end if;
  return _mm_check('admin', crypt(coalesce(p_pin,''), h) = h);
end $$;

-- 반환: 'OK:<uuid>' 또는 오류 코드
create or replace function public._mm_team(p_code text, p_pin text)
returns text language plpgsql security definer set search_path = public, extensions as $$
declare t mm_teams; r text;
begin
  select * into t from mm_teams where code = upper(trim(coalesce(p_code,'')));
  if t.id is null then return 'NO_TEAM'; end if;
  r := _mm_check('team:' || t.code, crypt(coalesce(p_pin,''), t.pin_hash) = t.pin_hash);
  if r = 'OK' then return 'OK:' || t.id::text; end if;
  return r;
end $$;

create or replace function public._mm_team_bundle(p_team uuid)
returns jsonb language sql security definer set search_path = public as $$
  select jsonb_build_object(
    'team', (select to_jsonb(t) - 'pin_hash' from mm_teams t where t.id = p_team),
    'sessions', coalesce((select jsonb_agg(to_jsonb(s) order by s.session_date, s.created_at) from mm_sessions s where s.team_id = p_team), '[]'::jsonb),
    'comments', coalesce((select jsonb_agg(to_jsonb(c) order by c.created_at) from mm_comments c where c.team_id = p_team), '[]'::jsonb),
    'notices',  coalesce((select jsonb_agg(to_jsonb(n) order by n.created_at desc) from mm_notices n where n.team_id is null or n.team_id = p_team), '[]'::jsonb)
  );
$$;

revoke all on function public._mm_check(text, boolean) from public, anon, authenticated;
revoke all on function public._mm_admin(text) from public, anon, authenticated;
revoke all on function public._mm_team(text, text) from public, anon, authenticated;
revoke all on function public._mm_team_bundle(uuid) from public, anon, authenticated;

-- ───── 교수자(관리자) ─────  모든 함수는 {"data": ...} 또는 {"error": "코드"} 를 반환합니다.
create or replace function public.mm_admin_status()
returns jsonb language sql security definer set search_path = public as $$
  select jsonb_build_object('data', exists(select 1 from mm_settings where id = 1));
$$;

create or replace function public.mm_admin_init(p_pin text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
begin
  if exists(select 1 from mm_settings) then return '{"error":"ALREADY_INITIALIZED"}'; end if;
  if length(coalesce(p_pin,'')) < 5 then return '{"error":"PIN_TOO_SHORT"}'; end if;
  insert into mm_settings(id, admin_pin_hash) values (1, crypt(p_pin, gen_salt('bf')));
  return '{"data":true}';
end $$;

create or replace function public.mm_admin_all(p_pin text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare a text := _mm_admin(p_pin);
begin
  if a <> 'OK' then return jsonb_build_object('error', a); end if;
  return jsonb_build_object('data', jsonb_build_object(
    'teams',    coalesce((select jsonb_agg(to_jsonb(t) - 'pin_hash' order by t.created_at) from mm_teams t), '[]'::jsonb),
    'sessions', coalesce((select jsonb_agg(to_jsonb(s) order by s.session_date, s.created_at) from mm_sessions s), '[]'::jsonb),
    'comments', coalesce((select jsonb_agg(to_jsonb(c) order by c.created_at) from mm_comments c), '[]'::jsonb),
    'notices',  coalesce((select jsonb_agg(to_jsonb(n) order by n.created_at desc) from mm_notices n), '[]'::jsonb)
  ));
end $$;

create or replace function public.mm_admin_save_team(p_pin text, p jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare a text := _mm_admin(p_pin); v_id uuid; v_code text;
begin
  if a <> 'OK' then return jsonb_build_object('error', a); end if;
  if coalesce(p->>'name','') = '' then return '{"error":"NAME_REQUIRED"}'; end if;
  if coalesce(p->>'id','') = '' then
    if length(coalesce(p->>'pin','')) < 4 then return '{"error":"PIN_TOO_SHORT"}'; end if;
    loop
      v_code := 'T' || upper(substr(md5(random()::text), 1, 5));
      exit when not exists(select 1 from mm_teams where code = v_code);
    end loop;
    insert into mm_teams(code, pin_hash, name, topic, example_set, mentor, mentee, goals)
    values (v_code, crypt(p->>'pin', gen_salt('bf')), p->>'name', coalesce(p->>'topic',''), coalesce(p->>'example_set','general'),
            coalesce(p->>'mentor',''), coalesce(p->>'mentee',''), coalesce(p->'goals','[]'::jsonb))
    returning id into v_id;
  else
    v_id := (p->>'id')::uuid;
    update mm_teams set name = p->>'name', topic = coalesce(p->>'topic',''), example_set = coalesce(p->>'example_set','general'),
      mentor = coalesce(p->>'mentor',''), mentee = coalesce(p->>'mentee',''),
      goals = coalesce(p->'goals','[]'::jsonb)
    where id = v_id;
    if length(coalesce(p->>'pin','')) >= 4 then
      update mm_teams set pin_hash = crypt(p->>'pin', gen_salt('bf')) where id = v_id;
    end if;
  end if;
  return jsonb_build_object('data', (select to_jsonb(t) - 'pin_hash' from mm_teams t where t.id = v_id));
end $$;

create or replace function public.mm_admin_delete_team(p_pin text, p_id uuid)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare a text := _mm_admin(p_pin);
begin
  if a <> 'OK' then return jsonb_build_object('error', a); end if;
  delete from mm_teams where id = p_id; return '{"data":true}';
end $$;

create or replace function public.mm_admin_delete_session(p_pin text, p_id uuid)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare a text := _mm_admin(p_pin);
begin
  if a <> 'OK' then return jsonb_build_object('error', a); end if;
  delete from mm_sessions where id = p_id; return '{"data":true}';
end $$;

create or replace function public.mm_admin_comment(p_pin text, p_session uuid, p_body text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare a text := _mm_admin(p_pin); v_team uuid;
begin
  if a <> 'OK' then return jsonb_build_object('error', a); end if;
  select team_id into v_team from mm_sessions where id = p_session;
  if v_team is null then return '{"error":"NO_SESSION"}'; end if;
  insert into mm_comments(session_id, team_id, role, author, body) values (p_session, v_team, 'admin', '교수자', p_body);
  return jsonb_build_object('data', v_team);
end $$;

create or replace function public.mm_admin_notice(p_pin text, p_team uuid, p_body text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare a text := _mm_admin(p_pin);
begin
  if a <> 'OK' then return jsonb_build_object('error', a); end if;
  insert into mm_notices(team_id, body) values (p_team, p_body); return '{"data":true}';
end $$;

create or replace function public.mm_admin_delete_notice(p_pin text, p_id uuid)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare a text := _mm_admin(p_pin);
begin
  if a <> 'OK' then return jsonb_build_object('error', a); end if;
  delete from mm_notices where id = p_id; return '{"data":true}';
end $$;

create or replace function public.mm_admin_purge(p_pin text, p_confirm text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare a text := _mm_admin(p_pin);
begin
  if a <> 'OK' then return jsonb_build_object('error', a); end if;
  if p_confirm <> '학기종료' then return '{"error":"CONFIRM_MISMATCH"}'; end if;
  delete from mm_notices where true;
  delete from mm_teams where true;   -- 활동기록·댓글은 cascade 로 함께 삭제
  delete from mm_attempts where true;
  return '{"data":true}';
end $$;

-- ───── 팀(멘토·멘티) ─────
create or replace function public.mm_team_login(p_code text, p_pin text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare a text := _mm_team(p_code, p_pin);
begin
  if a not like 'OK:%' then return jsonb_build_object('error', a); end if;
  return jsonb_build_object('data', _mm_team_bundle(substr(a, 4)::uuid));
end $$;

create or replace function public.mm_team_add_session(p_code text, p_pin text, p jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare a text := _mm_team(p_code, p_pin); v_team uuid; v_id uuid;
begin
  if a not like 'OK:%' then return jsonb_build_object('error', a); end if;
  v_team := substr(a, 4)::uuid;
  -- 활동 인증 사진(얼굴)과 학습 결과물 사진이 각각 1장 이상 있어야 저장
  if not exists (select 1 from jsonb_array_elements(coalesce(p->'photos','[]'::jsonb)) e where e->>'kind' = 'face')
     or not exists (select 1 from jsonb_array_elements(coalesce(p->'photos','[]'::jsonb)) e where e->>'kind' = 'output') then
    return '{"error":"PHOTO_REQUIRED"}';
  end if;
  insert into mm_sessions(team_id, session_date, minutes, mode, place, topic, content, output_link,
                          difficulty, next_plan, photos, self_rating, mentor_rating, gas, unit, narrative, author)
  values (v_team, (p->>'session_date')::date, coalesce((p->>'minutes')::int,0), coalesce(p->>'mode','대면'),
          coalesce(p->>'place',''), coalesce(p->>'topic',''), coalesce(p->>'content',''), coalesce(p->>'output_link',''),
          coalesce(p->>'difficulty',''), coalesce(p->>'next_plan',''), p->'photos',
          coalesce(p->'self_rating','{}'::jsonb), coalesce(p->'mentor_rating','{}'::jsonb),
          coalesce(p->'gas','{}'::jsonb), coalesce(p->>'unit',''), coalesce(p->'narrative','{}'::jsonb), coalesce(p->>'author',''))
  returning id into v_id;
  return jsonb_build_object('data', jsonb_build_object('id', v_id, 'team_id', v_team));
end $$;

create or replace function public.mm_team_comment(p_code text, p_pin text, p_session uuid, p_role text, p_author text, p_body text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare a text := _mm_team(p_code, p_pin); v_team uuid;
begin
  if a not like 'OK:%' then return jsonb_build_object('error', a); end if;
  v_team := substr(a, 4)::uuid;
  if p_role not in ('mentor','mentee') then return '{"error":"BAD_ROLE"}'; end if;
  if not exists(select 1 from mm_sessions where id = p_session and team_id = v_team) then return '{"error":"NO_SESSION"}'; end if;
  insert into mm_comments(session_id, team_id, role, author, body) values (p_session, v_team, p_role, p_author, p_body);
  return jsonb_build_object('data', v_team);
end $$;

drop function if exists public.mm_admin_login(text);
create or replace function public.mm_admin_login(p_pin text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare a text := _mm_admin(p_pin);
begin
  if a <> 'OK' then return jsonb_build_object('error', a); end if;
  return '{"data":true}';
end $$;

grant execute on function public.mm_admin_status() to anon, authenticated;
grant execute on function public.mm_admin_init(text) to anon, authenticated;
grant execute on function public.mm_admin_login(text) to anon, authenticated;
grant execute on function public.mm_admin_all(text) to anon, authenticated;
grant execute on function public.mm_admin_save_team(text, jsonb) to anon, authenticated;
grant execute on function public.mm_admin_delete_team(text, uuid) to anon, authenticated;
grant execute on function public.mm_admin_delete_session(text, uuid) to anon, authenticated;
grant execute on function public.mm_admin_comment(text, uuid, text) to anon, authenticated;
grant execute on function public.mm_admin_notice(text, uuid, text) to anon, authenticated;
grant execute on function public.mm_admin_delete_notice(text, uuid) to anon, authenticated;
grant execute on function public.mm_admin_purge(text, text) to anon, authenticated;
grant execute on function public.mm_team_login(text, text) to anon, authenticated;
grant execute on function public.mm_team_add_session(text, text, jsonb) to anon, authenticated;
grant execute on function public.mm_team_comment(text, text, uuid, text, text, text) to anon, authenticated;

-- ───── 활동 사진 저장소 ─────
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('mm-photos', 'mm-photos', true, 2097152, array['image/jpeg','image/png','image/webp'])
on conflict (id) do nothing;

drop policy if exists "mm photos upload" on storage.objects;
create policy "mm photos upload" on storage.objects
  for insert to anon, authenticated
  with check (bucket_id = 'mm-photos');
