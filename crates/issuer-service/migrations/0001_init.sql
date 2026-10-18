-- Issuer Service schema, R1.
--
-- Applied only by `aap-issuer-service migrate`, as the migration role. The
-- {{app_role}} placeholder is replaced with the (validated, quoted) name of
-- the least-privilege role the running service connects as.

create table users (
    user_id    uuid primary key,
    created_at timestamptz not null default now()
);

create table devices (
    device_id             uuid primary key,
    user_id               uuid not null references users (user_id),
    principal_jwk         jsonb not null,
    jwk_thumbprint        bytea not null unique check (octet_length(jwk_thumbprint) = 32),
    attestation_type      text not null check (attestation_type in ('app_attest')),
    -- App Attest key id exactly as iOS reports it (standard base64).
    app_attest_key_id     text not null unique,
    app_attest_public_key bytea not null check (octet_length(app_attest_public_key) = 65),
    app_id                text not null,
    environment           text not null check (environment in ('development', 'production')),
    counter               bigint not null default 0 check (counter between 0 and 4294967295),
    status                text not null default 'active' check (status in ('active', 'flagged', 'revoked')),
    flagged_at            timestamptz,
    flagged_reason        text,
    enrolled_at           timestamptz not null default now(),
    last_assertion_at     timestamptz
);
create index devices_user_idx on devices (user_id);

create table enrollment_challenges (
    challenge_id uuid primary key,
    challenge    bytea not null check (octet_length(challenge) = 32),
    created_at   timestamptz not null default now(),
    expires_at   timestamptz not null,
    consumed_at  timestamptz
);
create index enrollment_challenges_expires_idx on enrollment_challenges (expires_at);

-- Append-only. No foreign keys on purpose: the record must outlive its subjects.
create table audit_events (
    event_id    bigint generated always as identity primary key,
    occurred_at timestamptz not null default now(),
    event_type  text not null,
    user_id     uuid,
    device_id   uuid,
    detail      jsonb not null default '{}'::jsonb
);

-- Second line of defense behind the grants below: even a role that does hold
-- UPDATE/DELETE/TRUNCATE (the table owner, a misconfigured grant) cannot
-- change history without first dropping the trigger.
create function audit_events_append_only() returns trigger
language plpgsql as $$
begin
    raise exception 'audit_events is append-only (% blocked)', tg_op
        using errcode = 'insufficient_privilege';
end;
$$;

create trigger audit_events_no_update_delete
    before update or delete on audit_events
    for each row execute function audit_events_append_only();

create trigger audit_events_no_truncate
    before truncate on audit_events
    for each statement execute function audit_events_append_only();

-- Least privilege for the running service.
revoke all on users, devices, enrollment_challenges, audit_events from public;
grant usage on schema public to {{app_role}};
grant select, insert on users to {{app_role}};
grant select, insert on devices to {{app_role}};
grant update (counter, status, flagged_at, flagged_reason, last_assertion_at) on devices to {{app_role}};
grant select, insert, delete on enrollment_challenges to {{app_role}};
grant update (consumed_at) on enrollment_challenges to {{app_role}};
grant select, insert on audit_events to {{app_role}};
revoke update, delete, truncate on audit_events from {{app_role}};
