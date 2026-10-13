-- ASA Events registration backend - D1 (SQLite) schema
-- Apply with:  npx wrangler d1 execute asa-events --remote --file=./schema.sql

DROP TABLE IF EXISTS throttle;
DROP TABLE IF EXISTS otps;
DROP TABLE IF EXISTS checkins;
DROP TABLE IF EXISTS access_tokens;
DROP TABLE IF EXISTS registrations;
DROP TABLE IF EXISTS invitation_events;
DROP TABLE IF EXISTS invitations;
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS audit_log;

-- The single source of truth for every event the system has ever run. Adding
-- a future event is one INSERT here -- every report filter, dropdown, badge/
-- certificate, and confirmation email reads from this table, never from a
-- hardcoded list. code is the natural business key (invitations/
-- invitation_events/registrations.event_codes all reference it directly) --
-- no separate surrogate id. registration_open is deliberately NOT a plain
-- boolean: registration_closes_at (a timestamp) is the real mechanism
-- (createRegistration()'s openTargets check), admin UI just presents it as a
-- checkbox (checked = NULL/cleared, unchecked = set to now). visible_in_reports
-- is a pure display toggle -- hiding an event from filters never deletes or
-- otherwise affects its registrations/checkins/audit history.
CREATE TABLE events (
  code                   TEXT PRIMARY KEY,
  title_en               TEXT NOT NULL,
  title_ar               TEXT NOT NULL,
  short_name             TEXT,
  city                   TEXT,
  country                TEXT,
  venue                  TEXT,
  logo_path              TEXT, -- filename under register/, e.g. 'asa-logo.jpg'
  start_date             TEXT NOT NULL,
  end_date               TEXT NOT NULL,
  registration_closes_at TEXT, -- NULL/future = open; past = closed (see note above)
  visible_in_reports     INTEGER NOT NULL DEFAULT 1,
  display_order          INTEGER,
  is_active              INTEGER NOT NULL DEFAULT 1,
  created_at             TEXT,
  updated_at             TEXT
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

-- One row per person per event cluster, even when they attend more than one
-- event within that cluster: event_codes is a comma-joined list (e.g.
-- "WGITA-35-2026,KSC-SC18-2026"), not a foreign key, since a registration
-- can span several. email is deliberately NOT unique: the same person can
-- have a separate registration row for an unrelated event cluster (e.g.
-- Cairo in September vs. Luxor in December), since each is a genuinely
-- different trip with its own travel/passport details. createRegistration()
-- enforces "no duplicate within the same event(s)" at the application
-- layer instead (see the duplicate-registration check there).
CREATE TABLE registrations (
  registration_id     TEXT PRIMARY KEY,
  reference           TEXT NOT NULL UNIQUE,
  event_codes         TEXT NOT NULL,
  invitation_id       TEXT REFERENCES invitations(invitation_id),
  email               TEXT NOT NULL,
  full_name           TEXT,
  organization_name   TEXT,
  country             TEXT,
  attendance_mode     TEXT,
  role_in_delegation  TEXT,
  participant_tier    TEXT NOT NULL DEFAULT 'other', -- 'president' | 'vice_president' | 'other' -- protocol tier, admin-assigned only
  presentation_track  TEXT, -- 'wgita' | 'seminar' | 'ksc' | NULL -- which day/track a speaker's presentation is
                             -- allocated to, admin-assigned only (event_codes alone can't tell WGITA's Annual
                             -- Meeting day from its Seminar day apart, since both share the WGITA-35-2026 code)
  presentation_order  INTEGER, -- admin-assigned running order within presentation_track, NULL if not yet set
  visa_letter_needed  INTEGER DEFAULT 0,
  status              TEXT NOT NULL DEFAULT 'approved', -- auto-confirmed on submission; admin can still revert/reject
  registration_number TEXT,              -- assigned immediately on submission, distinct from reference
  data_json           TEXT NOT NULL,     -- full submission
  consents_json       TEXT,
  flag_personal_email INTEGER DEFAULT 0,
  flag_org_mismatch   INTEGER DEFAULT 0,
  source_ip_hash      TEXT,
  fill_seconds        INTEGER,
  locale              TEXT,
  created_at          TEXT NOT NULL,
  reminder_sent_at    TEXT,                -- last time an admin sent a "missing data" reminder email
  reminder_categories TEXT                 -- comma list of what that reminder covered, e.g. 'itinerary,hotel'
);
CREATE INDEX ix_reg_status ON registrations(status);

-- One row per (person, event) actually checked in at reception -- scanning a
-- dual-event participant's WGITA badge and their KSC badge writes two rows.
-- Added live via a non-destructive migration; kept here for fresh installs.
CREATE TABLE checkins (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  reference     TEXT NOT NULL REFERENCES registrations(reference),
  event_code    TEXT NOT NULL,
  checked_in_at TEXT NOT NULL,
  UNIQUE(reference, event_code)
);

-- Named, scoped tokens -- an alternative to the two shared secrets
-- (ADMIN_TOKEN/VIEWER_TOKEN) for handing access to one external recipient
-- or one staff role without giving them everything a viewer/admin token
-- would. Managed from admin/tokens; see ALL_SCOPES/resolveAccess() in the
-- worker. The token itself is never stored, only its SHA-256 hash.
CREATE TABLE access_tokens (
  token_id     TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  token_hash   TEXT NOT NULL UNIQUE,
  scopes       TEXT NOT NULL,          -- comma list, e.g. "report,dashboard,logistics"
  is_active    INTEGER NOT NULL DEFAULT 1,
  created_at   TEXT NOT NULL,
  last_used_at TEXT
);

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
  actor      TEXT,    -- self-reported "Your name" from the admin's browser (X-Actor-Name header); never
                       -- trusted for authorization, just a label since ADMIN_TOKEN/VIEWER_TOKEN are shared
  created_at TEXT NOT NULL
);

INSERT INTO events (code, title_en, title_ar, short_name, city, country, venue, logo_path, start_date, end_date, registration_closes_at, visible_in_reports, display_order, created_at, updated_at) VALUES
 ('WGITA-35-2026','INTOSAI Working Group on IT Audit','فريق عمل الإنتوساي المعني بتدقيق تكنولوجيا المعلومات','WGITA','Cairo','Arab Republic of Egypt','Steigenberger Pyramids Cairo Hotel, Giza','wgita-logo.jpg','2026-09-28','2026-09-29','2026-10-13T00:00:00+02:00',1,1,'2026-10-13T18:00:00Z','2026-10-13T18:00:00Z'),
 ('KSC-SC18-2026','KSC Steering Committee Meeting','اجتماع اللجنة التوجيهية لـ KSC','KSC','Cairo','Arab Republic of Egypt','Steigenberger Pyramids Cairo Hotel, Giza','intosai-logo.png','2026-09-30','2026-09-30','2026-10-13T00:00:00+02:00',1,2,'2026-10-13T18:00:00Z','2026-10-13T18:00:00Z'),
 ('TG-42-2026','Forty-second (2026) Meeting of the Technical Group','الاجتماع الثاني والأربعون (2026) للفريق الفني','TG','Luxor','Arab Republic of Egypt','Luxor, Arab Republic of Egypt','asa-logo.jpg','2026-12-02','2026-12-04','2026-12-01T23:59:00+02:00',1,3,'2026-10-13T18:00:00Z','2026-10-13T18:00:00Z'),
 ('UNPEA-66-2026','Sixty-sixth (2026) Regular Session of the UN Panel of External Auditors','الدورة العادية السادسة والستون (2026) للجنة المراجعين الخارجيين للأمم المتحدة','UNPEA','Luxor','Arab Republic of Egypt','Luxor, Arab Republic of Egypt','asa-logo.jpg','2026-12-07','2026-12-08','2026-12-01T23:59:00+02:00',1,4,'2026-10-13T18:00:00Z','2026-10-13T18:00:00Z');

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
