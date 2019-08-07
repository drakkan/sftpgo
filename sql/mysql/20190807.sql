BEGIN;
--
-- Rename field public_key on user to public_keys
--
ALTER TABLE `users` CHANGE `public_key` `public_keys` longtext NULL;
COMMIT;