# Groups

Using groups simplifies the administration of multiple accounts by letting you assign settings once to a group, instead of multiple times to each individual user.

SFTPGo supports two types of groups:

- primary groups
- secondary groups

A user can be a member of a primary group and many secondary groups. Depending on the group type, the settings are inherited differently.

:warning: SFTPGo groups are completely unrelated to system groups. Therefore, it is not necessary to add Linux/Windows groups to use SFTPGo groups.

The following settings are inherited from the primary group:

- home dir, if set for the group will replace the one defined for the user. The `%username%` placeholder is replaced with the username
- filesystem config, if the provider set for the group is different from the "local provider" will replace the one defined for the user. The `%username%` placeholder is replaced with the username within the defined "prefix", for any vfs, and the "username" for the SFTP filesystem config
- max sessions, quota size/files, upload/download bandwidth, upload/download/total data transfer, max upload size, external auth cache time, ftp_security, default share expiration: if they are set to `0` for the user they are replaced with the value set for the group, if different from `0`
- TLS username, check password hook disabled, pre-login hook disabled, external auth hook disabled, filesystem checks disabled, allow API key authentication, anonymous user: if they are not set for the user they are replaced with the value set for the group
- starting directory, if the user does not have a starting directory set, the value set for the group is used, if any. The `%username%` placeholder is replaced with the username

The following settings are inherited from the primary and secondary groups:

- virtual folders, file patterns, permissions: they are added to the user configuration if the user does not already have a setting for the configured path. The `/` path is ignored for secondary groups. The `%username%` placeholder is replaced with the username within the virtual path, the defined "prefix", for any vfs, and the "username" for the SFTP and HTTP filesystem config
- per-source bandwidth limits
- per-source data transfer limits
- allowed/denied IPs
- denied login methods and protocols
- two factor auth protocols
- web client/REST API permissions

The settings from the primary group are always merged first.

The final settings are a combination of the user settings and the group ones.
For example you can define the following groups:

- "group1", it has a virtual directory to mount on `/vdir1`
- "group2", it has a virtual directory to mount on `/vdir2`
- "group3", it has a virtual directory to mount on `/vdir3`

If you define users with a virtual directory to mount on `/vdir` and make them member of all the above groups, they will have virtual directories mounted on `/vdir`, `/vdir1`, `/vdir2`, `/vdir3`. If users already have a virtual directory to mount on `/vdir1`, the group's one will be ignored.

Please note that if the same virtual path is set in more than one secondary group the behavior is undefined. For example if a user is a member of two secondary groups and each secondary group defines a virtual folder to mount on the `/vdir2` path, the virtual folder mounted on `/vdir2` may change with every login.
