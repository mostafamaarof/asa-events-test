-- ASA Events registration backend - D1 (SQLite) schema
-- Apply with:  npx wrangler d1 execute asa-events --remote --file=./schema.sql

DROP TABLE IF EXISTS throttle;
DROP TABLE IF EXISTS otps;
DROP TABLE IF EXISTS registrations;
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
  event_code        TEXT NOT NULL REFERENCES events(code),
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

CREATE TABLE otps (
  email       TEXT NOT NULL,
  event_code  TEXT NOT NULL,
  otp_hash    TEXT NOT NULL,
  expires_at  INTEGER NOT NULL,
  attempts    INTEGER NOT NULL DEFAULT 0,
  invitation_id TEXT,
  PRIMARY KEY (email, event_code)
);

CREATE TABLE registrations (
  registration_id     TEXT PRIMARY KEY,
  reference           TEXT NOT NULL UNIQUE,
  event_code          TEXT NOT NULL REFERENCES events(code),
  invitation_id       TEXT REFERENCES invitations(invitation_id),
  email               TEXT NOT NULL,
  full_name           TEXT,
  organization_name   TEXT,
  country             TEXT,
  attendance_mode     TEXT,
  role_in_delegation  TEXT,
  visa_letter_needed  INTEGER DEFAULT 0,
  status              TEXT NOT NULL DEFAULT 'under_review',
  data_json           TEXT NOT NULL,     -- full submission
  consents_json       TEXT,
  flag_personal_email INTEGER DEFAULT 0,
  flag_org_mismatch   INTEGER DEFAULT 0,
  source_ip_hash      TEXT,
  fill_seconds        INTEGER,
  locale              TEXT,
  created_at          TEXT NOT NULL
);
CREATE UNIQUE INDEX ux_reg_event_email ON registrations(event_code, email);
CREATE INDEX ix_reg_status ON registrations(event_code, status);

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
 ('WGITA-35-2026','35th WGITA Annual Meeting','الاجتماع السنوي الخامس والثلاثون لفريق WGITA','2026-09-27','2026-09-29','2026-12-31T23:59:00+02:00'),
 ('KSC-SC18-2026','18th Meeting of the KSC Steering Committee','الاجتماع الثامن عشر للجنة التوجيهية لـ KSC','2026-09-30','2026-09-30','2026-12-31T23:59:00+02:00');

-- Two invitations so the public test link works out of the box.
INSERT INTO invitations (invitation_id, event_code, code, organization_name, country, org_type, liaison_email, max_uses, allow_free_email, expires_at, is_active) VALUES
 ('inv-demo-1','WGITA-35-2026','ASA-WGITA35-TST-4M7K','Test Supreme Audit Institution','EG','sai','liaison@example.org',NULL,0,'2026-12-31',1),
 ('inv-demo-2','WGITA-35-2026','ASA-DEMO-EXP-9K4T','Invited expert (personal email permitted)','EG','expert','liaison@example.org',NULL,1,'2026-12-31',1);
