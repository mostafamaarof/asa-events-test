-- Additive migration: a badge/registration number assigned only on approval,
-- distinct from the submission reference assigned at intake.
-- Apply with:  npx wrangler d1 execute asa-events --remote --file=./migrations/003_registration_number.sql

ALTER TABLE registrations ADD COLUMN registration_number TEXT;
