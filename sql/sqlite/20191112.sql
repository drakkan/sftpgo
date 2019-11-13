BEGIN;
--
-- Add field expiration_date to user
--
CREATE TABLE "new__users" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "expiration_date" bigint NOT NULL, "username" varchar(255) NOT NULL UNIQUE, "password" varchar(255) NULL, "public_keys" text NULL, "home_dir" varchar(255) NOT NULL, "uid" integer NOT NULL, "gid" integer NOT NULL, "max_sessions" integer NOT NULL, "quota_size" bigint NOT NULL, "quota_files" integer NOT NULL, "permissions" text NOT NULL, "used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL, "last_quota_update" bigint NOT NULL, "upload_bandwidth" integer NOT NULL, "download_bandwidth" integer NOT NULL);
INSERT INTO "new__users" ("id", "username", "password", "public_keys", "home_dir", "uid", "gid", "max_sessions", "quota_size", "quota_files", "permissions", "used_quota_size", "used_quota_files", "last_quota_update", "upload_bandwidth", "download_bandwidth", "expiration_date") SELECT "id", "username", "password", "public_keys", "home_dir", "uid", "gid", "max_sessions", "quota_size", "quota_files", "permissions", "used_quota_size", "used_quota_files", "last_quota_update", "upload_bandwidth", "download_bandwidth", 0 FROM "users";
DROP TABLE "users";
ALTER TABLE "new__users" RENAME TO "users";
--
-- Add field last_login to user
--
CREATE TABLE "new__users" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "username" varchar(255) NOT NULL UNIQUE, "password" varchar(255) NULL, "public_keys" text NULL, "home_dir" varchar(255) NOT NULL, "uid" integer NOT NULL, "gid" integer NOT NULL, "max_sessions" integer NOT NULL, "quota_size" bigint NOT NULL, "quota_files" integer NOT NULL, "permissions" text NOT NULL, "used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL, "last_quota_update" bigint NOT NULL, "upload_bandwidth" integer NOT NULL, "download_bandwidth" integer NOT NULL, "expiration_date" bigint NOT NULL, "last_login" bigint NOT NULL);
INSERT INTO "new__users" ("id", "username", "password", "public_keys", "home_dir", "uid", "gid", "max_sessions", "quota_size", "quota_files", "permissions", "used_quota_size", "used_quota_files", "last_quota_update", "upload_bandwidth", "download_bandwidth", "expiration_date", "last_login") SELECT "id", "username", "password", "public_keys", "home_dir", "uid", "gid", "max_sessions", "quota_size", "quota_files", "permissions", "used_quota_size", "used_quota_files", "last_quota_update", "upload_bandwidth", "download_bandwidth", "expiration_date", 0 FROM "users";
DROP TABLE "users";
ALTER TABLE "new__users" RENAME TO "users";
--
-- Add field status to user
--
CREATE TABLE "new__users" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "username" varchar(255) NOT NULL UNIQUE, "password" varchar(255) NULL, "public_keys" text NULL, "home_dir" varchar(255) NOT NULL, "uid" integer NOT NULL, "gid" integer NOT NULL, "max_sessions" integer NOT NULL, "quota_size" bigint NOT NULL, "quota_files" integer NOT NULL, "permissions" text NOT NULL, "used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL, "last_quota_update" bigint NOT NULL, "upload_bandwidth" integer NOT NULL, "download_bandwidth" integer NOT NULL, "expiration_date" bigint NOT NULL, "last_login" bigint NOT NULL, "status" integer NOT NULL);
INSERT INTO "new__users" ("id", "username", "password", "public_keys", "home_dir", "uid", "gid", "max_sessions", "quota_size", "quota_files", "permissions", "used_quota_size", "used_quota_files", "last_quota_update", "upload_bandwidth", "download_bandwidth", "expiration_date", "last_login", "status") SELECT "id", "username", "password", "public_keys", "home_dir", "uid", "gid", "max_sessions", "quota_size", "quota_files", "permissions", "used_quota_size", "used_quota_files", "last_quota_update", "upload_bandwidth", "download_bandwidth", "expiration_date", "last_login", 1 FROM "users";
DROP TABLE "users";
ALTER TABLE "new__users" RENAME TO "users";
COMMIT;