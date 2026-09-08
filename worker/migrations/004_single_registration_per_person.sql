-- Registrations move from one row per (event, person) to one row per
-- person, covering every event they selected (event_codes, comma-joined).
-- All registrations so far are test data — dropped and recreated rather
-- than migrated, per instruction.
-- Also refreshes the event titles/dates to the finalized programme.
-- Apply with:  npx wrangler d1 execute asa-events --remote --file=./migrations/004_single_registration_per_person.sql

DROP TABLE IF EXISTS registrations;

CREATE TABLE registrations (
  registration_id     TEXT PRIMARY KEY,
  reference           TEXT NOT NULL UNIQUE,
  event_codes         TEXT NOT NULL,
  invitation_id       TEXT REFERENCES invitations(invitation_id),
  email               TEXT NOT NULL UNIQUE,
  full_name           TEXT,
  organization_name   TEXT,
  country             TEXT,
  attendance_mode     TEXT,
  role_in_delegation  TEXT,
  visa_letter_needed  INTEGER DEFAULT 0,
  status              TEXT NOT NULL DEFAULT 'under_review',
  registration_number TEXT,
  data_json           TEXT NOT NULL,
  consents_json       TEXT,
  flag_personal_email INTEGER DEFAULT 0,
  flag_org_mismatch   INTEGER DEFAULT 0,
  source_ip_hash      TEXT,
  fill_seconds        INTEGER,
  locale              TEXT,
  created_at          TEXT NOT NULL
);
CREATE INDEX ix_reg_status ON registrations(status);

UPDATE events SET
  title_en = 'INTOSAI Working Group on IT Audit',
  title_ar = 'فريق عمل الإنتوساي المعني بتدقيق تكنولوجيا المعلومات',
  start_date = '2026-09-28',
  end_date = '2026-09-29'
WHERE code = 'WGITA-35-2026';

UPDATE events SET
  title_en = 'KSC Steering Committee Meeting',
  title_ar = 'اجتماع اللجنة التوجيهية لـ KSC'
WHERE code = 'KSC-SC18-2026';

-- Stale now that the registrations they counted are gone.
UPDATE invitations SET used_count = 0;
