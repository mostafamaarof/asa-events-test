-- Additive migration: invitation codes can cover more than one event.
-- Does not touch events / invitations / registrations data.
-- Apply with:  npx wrangler d1 execute asa-events --remote --file=./migrations/002_multi_event_invitations.sql

CREATE TABLE IF NOT EXISTS invitation_events (
  invitation_id TEXT NOT NULL REFERENCES invitations(invitation_id),
  event_code    TEXT NOT NULL REFERENCES events(code),
  PRIMARY KEY (invitation_id, event_code)
);
CREATE INDEX IF NOT EXISTS ix_ie_event ON invitation_events(event_code);

-- Backfill: every existing code keeps covering the single event it already had.
INSERT OR IGNORE INTO invitation_events (invitation_id, event_code)
SELECT invitation_id, event_code FROM invitations;

-- otps is a 10-minute ephemeral cache, not data worth preserving. Rebuilt
-- keyed by invitation (not event_code), since the applicant now picks
-- which covered event(s) to register for only after the OTP step.
DROP TABLE IF EXISTS otps;
CREATE TABLE otps (
  email         TEXT NOT NULL,
  invitation_id TEXT NOT NULL,
  otp_hash      TEXT NOT NULL,
  expires_at    INTEGER NOT NULL,
  attempts      INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (email, invitation_id)
);

-- One demo code that covers both events, for testing the new flow.
INSERT OR IGNORE INTO invitations (invitation_id, event_code, code, organization_name, country, org_type, liaison_email, max_uses, allow_free_email, expires_at, is_active) VALUES
 ('inv-demo-3','WGITA-35-2026','ASA-BOTH-TST-7Q2R','Both-events test delegate','EG','sai','liaison@example.org',NULL,1,'2026-12-31',1);
INSERT OR IGNORE INTO invitation_events (invitation_id, event_code) VALUES
 ('inv-demo-3','WGITA-35-2026'),
 ('inv-demo-3','KSC-SC18-2026');
