BEGIN;

CREATE TABLE IF NOT EXISTS fsmeta_folders
(
    id   serial not null
        constraint fsmeta_folders_pk primary key,
    path text   not null
);

CREATE UNIQUE INDEX fsmeta_folders_path_uindex
    ON fsmeta_folders (path);

CREATE TABLE IF NOT EXISTS fsmeta_files
(
    id            serial                   not null
        constraint fsmeta_files_pk primary key,
    folder_id     integer                  not null
        constraint fsmeta_files_fsmeta_folders_id_fk references fsmeta_folders,
    filename      text                     not null,
    uploaded      timestamp with time zone not null,
    filesize      integer default 0        not null,
    etag          text    default ''::text not null,
    last_modified timestamp with time zone not null
);

CREATE UNIQUE INDEX fsmeta_files_folder_id_filename_uindex
    ON fsmeta_files (folder_id, filename);

COMMIT;