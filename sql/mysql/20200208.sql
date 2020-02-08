BEGIN;
--
-- Create model SchemaVersion
--
CREATE TABLE `schema_version` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `version` integer NOT NULL);
---
--- Add initial version
---
INSERT INTO schema_version (version) VALUES (1);
COMMIT;