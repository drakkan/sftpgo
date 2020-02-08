BEGIN;
--
-- Create model SchemaVersion
--
CREATE TABLE "schema_version" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "version" integer NOT NULL);
---
--- Add initial version
---
INSERT INTO schema_version (version) VALUES (1);
COMMIT;
