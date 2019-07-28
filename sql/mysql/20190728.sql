BEGIN;
--
-- Rename field last_quota_scan on user to last_quota_update
--
ALTER TABLE `users` CHANGE `last_quota_scan` `last_quota_update` bigint NOT NULL;
COMMIT;