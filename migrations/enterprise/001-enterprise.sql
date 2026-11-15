-- CORP-012 enterprise integrations. Every table is tenant-scoped evidence or
-- queue state; none can alter register entries, frozen snapshots or votes.
CREATE TABLE app_charter.integration_events (
  provider text NOT NULL CHECK (provider IN ('captable','esign')),
  event_id text NOT NULL CHECK (char_length(event_id) BETWEEN 1 AND 200),
  tenant_id uuid NOT NULL REFERENCES dge_identity.tenants(id),
  kind text NOT NULL CHECK (char_length(kind) BETWEEN 1 AND 80),
  body_digest char(64) NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('recorded','captable-matches','captable-mismatch','rejected')),
  report jsonb,
  received_at timestamptz NOT NULL,
  PRIMARY KEY (provider, event_id)
);
CREATE INDEX integration_events_by_tenant ON app_charter.integration_events(tenant_id, received_at DESC);

CREATE TABLE app_charter.scim_users (
  tenant_id uuid NOT NULL REFERENCES dge_identity.tenants(id),
  external_id text NOT NULL CHECK (char_length(external_id) BETWEEN 1 AND 200),
  user_name text NOT NULL CHECK (char_length(user_name) BETWEEN 1 AND 254),
  account_id uuid REFERENCES dge_identity.accounts(id),
  active boolean NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, external_id)
);
CREATE TABLE app_charter.scim_deprovisions (
  tenant_id uuid NOT NULL REFERENCES dge_identity.tenants(id),
  id uuid NOT NULL,
  external_id text NOT NULL,
  account_id uuid REFERENCES dge_identity.accounts(id),
  requested_at timestamptz NOT NULL,
  applied_at timestamptz,
  applied_by uuid REFERENCES dge_identity.accounts(id),
  outcome text CHECK (outcome IN ('removed','not-a-member','unmatched','owner-protected')),
  PRIMARY KEY (tenant_id, id)
);

CREATE TABLE app_charter.webhook_endpoints (
  tenant_id uuid NOT NULL REFERENCES dge_identity.tenants(id),
  id uuid NOT NULL,
  url text NOT NULL CHECK (url ~ '^https://' AND char_length(url) <= 500),
  scopes text[] NOT NULL,
  secret_ciphertext bytea NOT NULL,
  created_by uuid NOT NULL REFERENCES dge_identity.accounts(id),
  created_at timestamptz NOT NULL,
  disabled_at timestamptz,
  minute_cursor bigint NOT NULL DEFAULT 0 CHECK (minute_cursor >= 0),
  PRIMARY KEY (tenant_id, id)
);
CREATE TABLE app_charter.webhook_deliveries (
  tenant_id uuid NOT NULL,
  endpoint_id uuid NOT NULL,
  event_id text NOT NULL,
  kind text NOT NULL,
  payload jsonb NOT NULL,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at timestamptz NOT NULL,
  delivered_at timestamptz,
  last_status integer,
  abandoned boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, endpoint_id, event_id),
  FOREIGN KEY (tenant_id, endpoint_id) REFERENCES app_charter.webhook_endpoints(tenant_id, id)
);
CREATE INDEX webhook_deliveries_due ON app_charter.webhook_deliveries(next_attempt_at) WHERE delivered_at IS NULL AND NOT abandoned;

GRANT SELECT, INSERT ON app_charter.integration_events, app_charter.scim_users, app_charter.scim_deprovisions,
  app_charter.webhook_endpoints, app_charter.webhook_deliveries TO dge_identity_runtime;
GRANT UPDATE (user_name, account_id, active, updated_at) ON app_charter.scim_users TO dge_identity_runtime;
GRANT UPDATE (applied_at, applied_by, outcome) ON app_charter.scim_deprovisions TO dge_identity_runtime;
GRANT UPDATE (disabled_at, minute_cursor) ON app_charter.webhook_endpoints TO dge_identity_runtime;
GRANT UPDATE (attempts, next_attempt_at, delivered_at, last_status, abandoned) ON app_charter.webhook_deliveries TO dge_identity_runtime;

-- Tenant-scoped reads and writes, as for the rest of app_charter. The outbound
-- delivery worker scans endpoints and deliveries across tenants; those two
-- tables hold only URLs, encrypted secrets and content-free event payloads.
DO $$ DECLARE target text; BEGIN
  FOREACH target IN ARRAY ARRAY['integration_events','scim_users','scim_deprovisions'] LOOP
    EXECUTE format('ALTER TABLE app_charter.%I ENABLE ROW LEVEL SECURITY',target);
    EXECUTE format('ALTER TABLE app_charter.%I FORCE ROW LEVEL SECURITY',target);
    EXECUTE format('CREATE POLICY tenant_scope ON app_charter.%I TO dge_identity_runtime USING (tenant_id::text=current_setting(''dge.tenant_id'',true)) WITH CHECK (tenant_id::text=current_setting(''dge.tenant_id'',true))',target);
  END LOOP;
END $$;
