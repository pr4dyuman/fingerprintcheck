create table if not exists visitor_profiles (
  visitor_id text primary key,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  visit_count int not null default 1,
  linked_id text,
  last_ip text,
  last_user_agent text,
  risk_label text,
  risk_score int,
  confidence_score numeric,
  last_request_id text,
  raw_fp_result jsonb,
  raw_client_signals jsonb,
  updated_at timestamptz not null default now()
);

create index if not exists idx_visitor_profiles_last_seen on visitor_profiles(last_seen_at desc);
create index if not exists idx_visitor_profiles_risk_label on visitor_profiles(risk_label);
