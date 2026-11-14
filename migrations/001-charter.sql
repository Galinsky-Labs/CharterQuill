-- CharterQuill application schema. Organization records are tenant-private;
-- nothing here is publicly readable. Engine tables are referenced, never altered.
CREATE SCHEMA app_charter;
REVOKE ALL ON SCHEMA app_charter FROM PUBLIC;
GRANT USAGE ON SCHEMA app_charter TO dge_identity_runtime;

CREATE TABLE app_charter.organizations (
  tenant_id uuid PRIMARY KEY REFERENCES dge_identity.tenants(id),
  entity_type text NOT NULL CHECK (entity_type IN ('corporation','llc','cooperative','nonprofit')),
  legal_name text NOT NULL CHECK (char_length(legal_name) BETWEEN 1 AND 300),
  jurisdiction text NOT NULL CHECK (char_length(jurisdiction) BETWEEN 1 AND 120),
  recusal_policy text NOT NULL DEFAULT 'exclude' CHECK (recusal_policy IN ('exclude','count-for-quorum')),
  created_by uuid NOT NULL REFERENCES dge_identity.accounts(id),
  created_at timestamptz NOT NULL
);
CREATE TABLE app_charter.governing_rules (
  tenant_id uuid NOT NULL REFERENCES app_charter.organizations(tenant_id),
  id uuid NOT NULL, version integer NOT NULL CHECK (version BETWEEN 1 AND 1000),
  rule jsonb NOT NULL, recorded_by uuid NOT NULL REFERENCES dge_identity.accounts(id), recorded_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id, version)
);
CREATE TABLE app_charter.share_classes (
  tenant_id uuid NOT NULL REFERENCES app_charter.organizations(tenant_id),
  id text NOT NULL CHECK (id ~ '^[a-z][a-z0-9-]{0,39}$'),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
  votes_per_share numeric(10,0) NOT NULL CHECK (votes_per_share >= 0),
  scale smallint NOT NULL CHECK (scale BETWEEN 0 AND 18),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
-- Register entries are append-only positions: a later entry supersedes an
-- earlier one for the same holder and class from its effective date.
CREATE TABLE app_charter.register_entries (
  tenant_id uuid NOT NULL,
  sequence bigint NOT NULL,
  holder_account_id uuid NOT NULL REFERENCES dge_identity.accounts(id),
  class_id text NOT NULL,
  units numeric(78,0) NOT NULL CHECK (units >= 0),
  effective_date date NOT NULL,
  beneficial_owner_ref text CHECK (beneficial_owner_ref IS NULL OR beneficial_owner_ref ~ '^[A-Za-z0-9._:-]{1,120}$'),
  import_batch uuid NOT NULL,
  recorded_by uuid NOT NULL REFERENCES dge_identity.accounts(id),
  recorded_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, sequence),
  FOREIGN KEY (tenant_id, class_id) REFERENCES app_charter.share_classes(tenant_id, id)
);
CREATE INDEX register_by_holder ON app_charter.register_entries(tenant_id, holder_account_id, class_id, effective_date);
CREATE TABLE app_charter.record_snapshots (
  tenant_id uuid NOT NULL, id uuid NOT NULL, record_date date NOT NULL,
  snapshot jsonb NOT NULL, digest char(64) NOT NULL, created_by uuid NOT NULL, created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE TABLE app_charter.meetings (
  tenant_id uuid NOT NULL, id uuid NOT NULL, meeting jsonb NOT NULL,
  status text NOT NULL DEFAULT 'scheduled' CHECK (status IN ('scheduled','held','cancelled')),
  created_by uuid NOT NULL, created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE TABLE app_charter.notices (
  tenant_id uuid NOT NULL, meeting_id uuid NOT NULL, recipient_id uuid NOT NULL REFERENCES dge_identity.accounts(id),
  method text NOT NULL CHECK (method IN ('email','in-app','mail','hand')),
  delivered_at timestamptz NOT NULL, recorded_by uuid NOT NULL, recorded_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, meeting_id, recipient_id, delivered_at),
  FOREIGN KEY (tenant_id, meeting_id) REFERENCES app_charter.meetings(tenant_id, id)
);
CREATE TABLE app_charter.consents (
  tenant_id uuid NOT NULL, id uuid NOT NULL, title text NOT NULL, body text NOT NULL,
  resolution_text text NOT NULL CHECK (char_length(resolution_text) BETWEEN 1 AND 100000),
  text_digest char(64) NOT NULL, eligible uuid[] NOT NULL, threshold_numerator integer NOT NULL, threshold_denominator integer NOT NULL,
  closes_at timestamptz NOT NULL, created_by uuid NOT NULL, created_at timestamptz NOT NULL,
  CHECK (threshold_numerator BETWEEN 1 AND threshold_denominator AND cardinality(eligible) BETWEEN 1 AND 1000),
  PRIMARY KEY (tenant_id, id)
);
CREATE TABLE app_charter.consent_signatures (
  tenant_id uuid NOT NULL, consent_id uuid NOT NULL, account_id uuid NOT NULL REFERENCES dge_identity.accounts(id),
  choice text NOT NULL CHECK (choice IN ('consent','withhold')), text_digest char(64) NOT NULL, signed_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, consent_id, account_id),
  FOREIGN KEY (tenant_id, consent_id) REFERENCES app_charter.consents(tenant_id, id)
);
CREATE TABLE app_charter.interests (
  tenant_id uuid NOT NULL, id uuid NOT NULL, account_id uuid NOT NULL REFERENCES dge_identity.accounts(id),
  interest jsonb NOT NULL, subject text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 300),
  recorded_at timestamptz NOT NULL, PRIMARY KEY (tenant_id, id)
);
CREATE TABLE app_charter.minute_entries (
  tenant_id uuid NOT NULL, sequence integer NOT NULL CHECK (sequence >= 1),
  entry jsonb NOT NULL, digest char(64) NOT NULL, recorded_by uuid NOT NULL, recorded_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, sequence)
);
CREATE TABLE app_charter.retention_schedules (
  tenant_id uuid NOT NULL, record_class text NOT NULL, version integer NOT NULL,
  schedule jsonb NOT NULL, recorded_by uuid NOT NULL, recorded_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, record_class, version)
);
CREATE TABLE app_charter.legal_holds (
  tenant_id uuid NOT NULL, id uuid NOT NULL, name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
  record_classes text[] NOT NULL, placed_by uuid NOT NULL, placed_at timestamptz NOT NULL,
  released_by uuid, released_at timestamptz,
  PRIMARY KEY (tenant_id, id), CHECK ((released_by IS NULL) = (released_at IS NULL))
);
CREATE TABLE app_charter.access_log (
  tenant_id uuid NOT NULL, id uuid NOT NULL, account_id uuid NOT NULL, action text NOT NULL CHECK (char_length(action) <= 60),
  subject text NOT NULL CHECK (char_length(subject) <= 200), at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX access_log_time ON app_charter.access_log(tenant_id, at DESC);

DO $$ DECLARE target text; BEGIN
  FOREACH target IN ARRAY ARRAY['organizations','governing_rules','share_classes','register_entries','record_snapshots','meetings','notices','consents','consent_signatures','interests','minute_entries','retention_schedules','legal_holds','access_log'] LOOP
    EXECUTE format('ALTER TABLE app_charter.%I ENABLE ROW LEVEL SECURITY',target);
    EXECUTE format('ALTER TABLE app_charter.%I FORCE ROW LEVEL SECURITY',target);
    EXECUTE format('CREATE POLICY tenant_scope ON app_charter.%I TO dge_identity_runtime USING (tenant_id::text=current_setting(''dge.tenant_id'',true)) WITH CHECK (tenant_id::text=current_setting(''dge.tenant_id'',true))',target);
  END LOOP;
END $$;
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA app_charter TO dge_identity_runtime;
GRANT UPDATE (status) ON app_charter.meetings TO dge_identity_runtime;
GRANT UPDATE (released_by, released_at) ON app_charter.legal_holds TO dge_identity_runtime;
GRANT UPDATE (recusal_policy) ON app_charter.organizations TO dge_identity_runtime;

CREATE FUNCTION app_charter.reject_change() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  RAISE EXCEPTION 'CharterQuill records are append-only';
END $$;
DO $$ DECLARE target text; BEGIN
  FOREACH target IN ARRAY ARRAY['governing_rules','register_entries','record_snapshots','notices','consents','consent_signatures','interests','minute_entries','retention_schedules','access_log'] LOOP
    EXECUTE format('CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON app_charter.%I FOR EACH ROW EXECUTE FUNCTION app_charter.reject_change()',target);
  END LOOP;
END $$;
-- A released hold stays on record; it cannot be re-opened or edited.
CREATE FUNCTION app_charter.guard_hold() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  IF OLD.released_at IS NOT NULL THEN RAISE EXCEPTION 'Released legal holds are final'; END IF;
  IF NEW.name<>OLD.name OR NEW.record_classes<>OLD.record_classes OR NEW.placed_at<>OLD.placed_at THEN RAISE EXCEPTION 'Legal holds cannot be edited'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER guard_hold BEFORE UPDATE ON app_charter.legal_holds FOR EACH ROW EXECUTE FUNCTION app_charter.guard_hold();
CREATE TRIGGER no_delete BEFORE DELETE ON app_charter.legal_holds FOR EACH ROW EXECUTE FUNCTION app_charter.reject_change();
