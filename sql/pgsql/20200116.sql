BEGIN;
--
-- Add field filesystem to user
--
ALTER TABLE "users" ADD COLUMN "filesystem" text NULL;
COMMIT;