# Virtual Folders

A virtual folder is a mapping between a SFTPGo virtual path and a filesystem path outside the user home directory or on a different storage provider.

For example, you can have a local user with an S3-based virtual folder or vice versa.

SFTPGo will try to automatically create any missing parent directory for the configured virtual folders at user login.

For each virtual folder, the following properties can be configured:

- `folder_name`, is the ID for an existings folder. The folder structure contains the absolute filesystem path to expose as virtual folder
- `filesystem`, this way you can map a local path or a Cloud backend to mount as virtual folders
- `virtual_path`, the SFTPGo absolute path to use to expose the mapped path
- `quota_size`, maximum size allowed as bytes. 0 means unlimited, -1 included in user quota
- `quota_files`, maximum number of files allowed. 0 means unlimited, -1 included in user quota

For example if a folder is configured to use `/tmp/mapped` or `C:\mapped` as filesystem path and `/vfolder` as virtual path then SFTPGo users can access `/tmp/mapped` or `C:\mapped` via the `/vfolder` virtual path.

Nested SFTP folders using the same SFTPGo instance (identified using the host keys) are not allowed as they could cause infinite SFTP loops.

The same virtual folder can be shared among users, different folder quota limits for each user are supported.
Folder quota limits can also be included inside the user quota but in this case the folder is considered "private" and sharing it with other users will break user quota calculation.
The calculation of the quota for a given user is obtained as the sum of the files contained in his home directory and those within each defined virtual folder included in its quota.

If you define folders that point to nested paths or to the same path, the quota calculation will be incorrect. Example:

- `folder1` uses `/srv/data/mapped` or `C:\mapped` as mapped path
- `folder2` uses `/srv/data/mapped/subdir` or `C:\mapped\subdir` as mapped path

If you upload a file to `folder2` its quota will be updated but the quota of `folder1` will not. We allow this for more flexibility, but if you want to enforce disk quotas using SFTPGo, avoid folders with nested paths.

It is allowed to mount a virtual folder in the user's root path (`/`). This might be useful if you want to share the same virtual folder between different users. In this case the user's root filesystem is hidden from the virtual folder.

Using the REST API you can:

- monitor folders quota usage
- scan quota for folders
- inspect the relationships among users and folders
- delete a virtual folder. SFTPGo removes folders from the data provider, no files deletion will occur

If you remove a folder, from the data provider, any users relationships will be cleared up. If the deleted folder is mounted on the user's root (`/`) path, the user is still valid and its root filesystem will no longer be hidden. If the deleted folder is included inside the user quota you need to do a user quota scan to update its quota. An orphan virtual folder will not be automatically deleted since if you add it again later then a quota scan is needed and it could be quite expensive, anyway you can easily list the orphan folders using the REST API and delete them if they are not needed anymore.
