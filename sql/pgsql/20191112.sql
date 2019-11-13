BEGIN;
--
-- Add field expiration_date to user
--
ALTER TABLE "users" ADD COLUMN "expiration_date" bigint DEFAULT 0 NOT NULL;
ALTER TABLE "users" ALTER COLUMN "expiration_date" DROP DEFAULT;
--
-- Add field last_login to user
--
ALTER TABLE "users" ADD COLUMN "last_login" bigint DEFAULT 0 NOT NULL;
ALTER TABLE "users" ALTER COLUMN "last_login" DROP DEFAULT;
--
-- Add field status to user
--
ALTER TABLE "users" ADD COLUMN "status" integer DEFAULT 1 NOT NULL;
ALTER TABLE "users" ALTER COLUMN "status" DROP DEFAULT;
COMMIT;