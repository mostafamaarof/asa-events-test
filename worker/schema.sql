-- ASA Events registration backend - D1 (SQLite) schema
-- Apply with:  npx wrangler d1 execute asa-events --remote --file=./schema.sql

DROP TABLE IF EXISTS throttle;
DROP TABLE IF EXISTS otps;
DROP TABLE IF EXISTS registrations;
DROP TABLE IF EXISTS invitation_events;
DROP TABLE IF EXISTS invitations;
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS audit_log;

CREATE TABLE events (
  code                   TEXT PRIMARY KEY,
  title_en               TEXT NOT NULL,
  title_ar               TEXT NOT NULL,
  start_date             TEXT NOT NULL,
  end_date               TEXT NOT NULL,
  registration_closes_at TEXT,
  is_active              INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE invitations (
  invitation_id     TEXT PRIMARY KEY,
  event_code        TEXT NOT NULL REFERENCES events(code),  -- legacy: first covered event, kept for compatibility
  code              TEXT NOT NULL UNIQUE,
  organization_name TEXT NOT NULL,
  country           TEXT,
  org_type          TEXT,
  liaison_email     TEXT,
  max_uses          INTEGER,              -- NULL = no cap, the agreed policy
  used_count        INTEGER NOT NULL DEFAULT 0,
  allow_free_email  INTEGER NOT NULL DEFAULT 0,
  expires_at        TEXT,
  is_active         INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX ix_inv_event ON invitations(event_code);

-- One invitation can cover more than one event (e.g. a delegate invited to
-- both WGITA and the KSC meeting back-to-back). This table is the source of
-- truth for which events a code actually unlocks; invitations.event_code
-- above is kept only as a legacy display fallback.
CREATE TABLE invitation_events (
  invitation_id TEXT NOT NULL REFERENCES invitations(invitation_id),
  event_code    TEXT NOT NULL REFERENCES events(code),
  PRIMARY KEY (invitation_id, event_code)
);
CREATE INDEX ix_ie_event ON invitation_events(event_code);

-- Keyed by invitation, not event: the applicant picks which covered
-- event(s) to register for only after the OTP step, so no single event_code
-- is known yet when the code is sent.
CREATE TABLE otps (
  email         TEXT NOT NULL,
  invitation_id TEXT NOT NULL,
  otp_hash      TEXT NOT NULL,
  expires_at    INTEGER NOT NULL,
  attempts      INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (email, invitation_id)
);

-- One row per person, even when they attend more than one event: event_codes
-- is a comma-joined list (e.g. "WGITA-35-2026,KSC-SC18-2026"), not a foreign
-- key, since a registration can span several. A person registers once.
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
  registration_number TEXT,              -- assigned only on approval, distinct from reference
  data_json           TEXT NOT NULL,     -- full submission
  consents_json       TEXT,
  flag_personal_email INTEGER DEFAULT 0,
  flag_org_mismatch   INTEGER DEFAULT 0,
  source_ip_hash      TEXT,
  fill_seconds        INTEGER,
  locale              TEXT,
  created_at          TEXT NOT NULL
);
CREATE INDEX ix_reg_status ON registrations(status);

CREATE TABLE throttle (
  k        TEXT PRIMARY KEY,
  n        INTEGER NOT NULL,
  reset_at INTEGER NOT NULL
);

CREATE TABLE audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  action     TEXT NOT NULL,
  entity     TEXT,
  entity_id  TEXT,
  detail     TEXT,
  ip_hash    TEXT,
  created_at TEXT NOT NULL
);

INSERT INTO events (code, title_en, title_ar, start_date, end_date, registration_closes_at) VALUES
 ('WGITA-35-2026','INTOSAI Working Group on IT Audit','فريق عمل الإنتوساي المعني بتدقيق تكنولوجيا المعلومات','2026-09-28','2026-09-29','2026-12-31T23:59:00+02:00'),
 ('KSC-SC18-2026','KSC Steering Committee Meeting','اجتماع اللجنة التوجيهية لـ KSC','2026-09-30','2026-09-30','2026-12-31T23:59:00+02:00');

-- Three invitations so the public test link works out of the box.
INSERT INTO invitations (invitation_id, event_code, code, organization_name, country, org_type, liaison_email, max_uses, allow_free_email, expires_at, is_active) VALUES
 ('inv-demo-1','WGITA-35-2026','ASA-WGITA35-TST-4M7K','Test Supreme Audit Institution','EG','sai','liaison@example.org',NULL,0,'2026-12-31',1),
 ('inv-demo-2','WGITA-35-2026','ASA-DEMO-EXP-9K4T','Invited expert (personal email permitted)','EG','expert','liaison@example.org',NULL,1,'2026-12-31',1),
 ('inv-demo-3','WGITA-35-2026','ASA-BOTH-TST-7Q2R','Both-events test delegate','EG','sai','liaison@example.org',NULL,1,'2026-12-31',1);

INSERT INTO invitation_events (invitation_id, event_code) VALUES
 ('inv-demo-1','WGITA-35-2026'),
 ('inv-demo-2','WGITA-35-2026'),
 ('inv-demo-3','WGITA-35-2026'),
 ('inv-demo-3','KSC-SC18-2026');
