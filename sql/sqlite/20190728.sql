BEGIN;
--
-- Rename field last_quota_scan on user to last_quota_update
--
ALTER TABLE "users" RENAME COLUMN "last_quota_scan" TO "last_quota_update";
COMMIT;