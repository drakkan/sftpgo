BEGIN;
--
-- Add field filesystem to user
--
ALTER TABLE `users` ADD COLUMN `filesystem` longtext NULL;
COMMIT;