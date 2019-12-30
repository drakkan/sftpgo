BEGIN;
--
-- Add field filters to user
--
ALTER TABLE "users" ADD COLUMN "filters" text NULL;
COMMIT;