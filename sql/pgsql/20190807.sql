BEGIN;
--
-- Rename field public_key on user to public_keys
--
ALTER TABLE "users" RENAME COLUMN "public_key" TO "public_keys";
COMMIT;