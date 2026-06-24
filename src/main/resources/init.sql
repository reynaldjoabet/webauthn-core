create table webauthn_credentials (
  id uuid primary key,
  tenant_id uuid not null,
  user_account_id uuid not null,

  user_handle bytea not null,
  rp_id text not null,

  credential_type text not null,
  credential_id bytea not null,

  public_key_cose bytea not null,
  cose_algorithm integer not null,

  sign_count bigint not null,
  uv_initialized boolean not null,

  transports text[] not null default array[]::text[],

  backup_eligible boolean not null,
  backup_state boolean not null,

  aaguid bytea null,
  attestation_format text not null,
  attestation_object bytea null,
  attestation_client_data_json bytea null,

  nickname text null,
  created_at timestamptz not null,
  last_used_at timestamptz null,
  disabled_at timestamptz null,

  constraint uq_webauthn_credentials_credential unique (tenant_id, rp_id, credential_id),
  constraint ck_webauthn_credentials_sign_count check (sign_count >= 0),
  constraint ck_webauthn_credentials_user_handle_len check (octet_length(user_handle) between 1 and 64),
  constraint ck_webauthn_credentials_credential_id_len check (octet_length(credential_id) between 1 and 1023),
  constraint ck_webauthn_credentials_aaguid_len check (aaguid is null or octet_length(aaguid) = 16),
  constraint ck_webauthn_credentials_backup_flags check (backup_eligible = true or backup_state = false)
);

create index idx_webauthn_credentials_user
  on webauthn_credentials (tenant_id, user_account_id)
  where disabled_at is null;

create table webauthn_ceremonies (
  id uuid primary key,
  tenant_id uuid not null,
  ceremony_type text not null,

  rp_id text not null,
  origin text not null,

  user_account_id uuid null,
  user_handle bytea null,

  challenge bytea not null,

  requested_user_verification text not null,
  attestation text null,

  allow_credential_ids bytea[] not null default array[]::bytea[],
  exclude_credential_ids bytea[] not null default array[]::bytea[],

  created_at timestamptz not null,
  expires_at timestamptz not null,
  consumed_at timestamptz null,

  constraint ck_webauthn_ceremonies_type check (ceremony_type in ('registration', 'authentication')),
  constraint ck_webauthn_ceremonies_challenge_len check (octet_length(challenge) = 32),
  constraint ck_webauthn_ceremonies_user_handle_len check (user_handle is null or octet_length(user_handle) between 1 and 64)
);

create index idx_webauthn_ceremonies_unconsumed_expiry
  on webauthn_ceremonies (expires_at)
  where consumed_at is null;

-- Consume atomically with a single update statement, e.g.:
--
-- update webauthn_ceremonies
--    set consumed_at = now()
--  where id = :id
--    and consumed_at is null
--    and expires_at > now()
-- returning *;
