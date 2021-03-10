# Virtual Folders

A virtual folder is a mapping between a SFTPGo virtual path and a filesystem path outside the user home directory.
The specified paths must be absolute and the virtual path cannot be "/", it must be a sub directory.
The parent directory to the specified virtual path must exist. SFTPGo will try to automatically create any missing parent directory for the configured virtual folders at user login.

For each virtual folder, the following properties can be configured:

- `folder_name`, is the ID for an existings folder. The folder structure contains the absolute filesystem path to expose as virtual folder
- `virtual_path`, the SFTPGo absolute path to use to expose the mapped path
- `quota_size`, maximum size allowed as bytes. 0 means unlimited, -1 included in user quota
- `quota_files`, maximum number of files allowed. 0 means unlimited, -1 included in user quota

For example if the configure folder has configured `/tmp/mapped` or `C:\mapped` as filesystem path and you set `/vfolder` as virtual path then SFTPGo users can access `/tmp/mapped` or `C:\mapped` via the `/vfolder` virtual path.

The same virtual folder can be shared among users, different folder quota limits for each user are supported.
Folder quota limits can also be included inside the user quota but in this case the folder is considered "private" and sharing it with other users will break user quota calculation.

Using the REST API you can:

- monitor folders quota usage
- scan quota for folders
- inspect the relationships among users and folders
- delete a virtual folder. SFTPGo removes folders from the data provider, no files deletion will occur

If you remove a folder, from the data provider, any users relationships will be cleared up. If the deleted folder is included inside the user quota you need to do a user quota scan to update its quota. An orphan virtual folder will not be automatically deleted since if you add it again later then a quota scan is needed and it could be quite expensive, anyway you can easily list the orphan folders using the REST API and delete them if they are not needed anymore.

Overlapping virtual paths are not allowed for the same user, overlapping mapped paths are allowed only if quota tracking is globally disabled inside the configuration file (`track_quota` must be set to `0`).
Virtual folders are supported for local filesystem only.
