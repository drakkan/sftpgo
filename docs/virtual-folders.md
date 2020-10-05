# Virtual Folders

A virtual folder is a mapping between an SFTP/SCP virtual path and a filesystem path outside the user home directory.
The specified paths must be absolute and the virtual path cannot be "/", it must be a sub directory.
The parent directory to the specified virtual path must exist. SFTPGo will try to automatically create any missing parent directory for the configured virtual folders at user login.

For each virtual folder, the following properties can be configured:

- `mapped_path`, the full absolute path to the filesystem path to expose as virtual folder
- `virtual_path`, the SFTP/SCP absolute path to use to expose the mapped path
- `quota_size`, maximum size allowed as bytes. 0 means unlimited, -1 included in user quota
- `quota_files`, maximum number of files allowed. 0 means unlimited, -1 included in user quota

For example if you configure `/tmp/mapped` or `C:\mapped` as mapped path and `/vfolder` as virtual path then SFTP/SCP users can access the mapped path via the `/vfolder` SFTP path.

The same virtual folder, identified by the `mapped_path`, can be shared among users and different folder quota limits for each user are supported.
Folder quota limits can also be included inside the user quota but in this case the folder is considered "private" and sharing it with other users will break user quota calculation.

You don't need to create virtual folders, inside the data provider, to associate them to the users: any missing virtual folder will be automatically created when you add/update a user. You only have to create the folder on the filesystem.

Using the REST API you can:

- monitor folders quota usage
- scan quota for folders
- inspect the relationships among users and folders
- delete a virtual folder. SFTPGo removes folders from the data provider, no files deletion will occur

If you remove a folder, from the data provider, any users relationships will be cleared up. If the deleted folder is included inside the user quota you need to do a user quota scan to update its quota. An orphan virtual folder will not be automatically deleted since if you add it again later then a quota scan is needed and it could be quite expensive, anyway you can easily list the orphan folders using the REST API and delete them if they are not needed anymore.

Overlapping virtual paths are not allowed for the same user, overlapping mapped paths are allowed only if quota tracking is globally disabled inside the configuration file (`track_quota` must be set to `0`).
Virtual folders are supported for local filesystem only.
