# Event Manager

The Event Manager allows an administrator to configure HTTP notifications, commands execution, email notifications and carry out certain server operations based on server events or schedules.

The following actions are supported:

- `HTTP notification`. You can notify an HTTP/S endpoing via GET, POST, PUT methods. You can define custom headers, query parameters and a body for POST and PUT request. Placeholders are supported for username, body, header and query parameter values.
- `Command execution`. You can launch custom commands passing parameters via environment variables. Placeholders are supported for environment variable values.
- `Email notification`. Placeholders are supported in subject and body. The email will be sent as plain text. For this action to work you have to configure an SMTP server in the SFTPGo configuration file.
- `Backup`. A backup will be saved in the configured backup directory. The backup will contain the week day and the hour in the file name.
- `User quota reset`. The quota used by users will be updated based on current usage.
- `Folder quota reset`. The quota used by virtual folders will be updated based on current usage.
- `Transfer quota reset`. The transfer quota values will be reset to `0`.
- `Data retention check`. You can define per-folder retention policies.
- `Metadata check`. A metadata check requires a metadata plugin such as [this one](https://github.com/sftpgo/sftpgo-plugin-metadata) and removes the metadata associated to missing items (for example objects deleted outside SFTPGo). A metadata check does nothing is no metadata plugin is installed or external metadata are not supported for a filesystem.
- `Filesystem`. For these actions, the required permissions are automatically granted. This is the same as executing the actions from an SFTP client and the same restrictions applies. Supported actions:
  - `Rename`. You can rename one or more files or directories.
  - `Delete`. You can delete one or more files and directories.
  - `Create directories`. You can create one or more directories including sub-directories.
  - `Path exists`. Check if the specified path exists.

The following placeholders are supported:

- `{{Name}}`. Username, folder name or admin username for provider events.
- `{{Event}}`. Event name, for example `upload`, `download` for filesystem events or `add`, `update` for provider events.
- `{{Status}}`. Status for `upload`, `download` and `ssh_cmd` events. 1 means no error, 2 means a generic error occurred, 3 means quota exceeded error.
- `{{StatusString}}`. Status as string. Possible values "OK", "KO".
- `{{ErrorString}}`. Error details. Replaced with an empty string if no errors occur.
- `{{VirtualPath}}`. Path seen by SFTPGo users, for example `/adir/afile.txt`.
- `{{FsPath}}`. Full filesystem path, for example `/user/homedir/adir/afile.txt` or `C:/data/user/homedir/adir/afile.txt` on Windows.
- `{{ObjectName}}`. File/directory name, for example `afile.txt` or provider object name.
- `{{ObjectType}}`. Object type for provider events: `user`, `group`, `admin`, etc.
- `{{VirtualTargetPath}}`. Virtual target path for renames.
- `{{FsTargetPath}}`. Full filesystem target path for renames.
- `{{FileSize}}`. File size.
- `{{Protocol}}`. Used protocol, for example `SFTP`, `FTP`.
- `{{IP}}`. Client IP address.
- `{{Timestamp}}`. Event timestamp as nanoseconds since epoch.
- `{{ObjectData}}`. Provider object data serialized as JSON with sensitive fields removed.
- `{{RetentionReports}}`. Data retention reports as zip compressed CSV files. Supported as email attachment, file path for multipart HTTP request and as single parameter for HTTP requests body. Data retention reports contain details on the number of files deleted and the total size deleted for each folder.

Event rules are based on the premise that an event occours. To each rule you can associate one or more actions.
The following trigger events are supported:

- `Filesystem events`, for example `upload`, `download` etc.
- `Provider events`, for example `add`, `update`, `delete` user or other resources.
- `Schedules`. The scheduler uses UTC time.
- `IP Blocked`, this event can be generated if you enable the [defender](./defender.md).
- `Certificate`, this event is generated when a certificate is renewed using the built-in ACME protocol. Both successful and failed renewals are notified.

You can further restrict a rule by specifying additional conditions that must be met before the rule’s actions are taken. For example you can react to uploads only if they are performed by a particular user or using a specified protocol.

Actions such as user quota reset, transfer quota reset, data retention check, folder quota reset and filesystem events are executed for all matching users if the trigger is a schedule or for the affected user if the trigger is a provider event or a filesystem action.

Actions are executed in a sequential order except for sync actions that are executed before the others. For each action associated to a rule you can define the following settings:

- `Stop on failure`, the next action will not be executed if the current one fails.
- `Failure action`, this action will be executed only if at least another one fails. :warning: Please note that a failure action isn't executed if the event fails, for example if a download fails the main action is executed. The failure action is executed only if one of the non-failure actions associated to a rule fails.
- `Execute sync`, for upload events, you can execute the action synchronously. Executing an action synchronously means that SFTPGo will not return a result code to the client (which is waiting for it) until your action have completed its execution. If your acion takes a long time to complete this could cause a timeout on the client side, which wouldn't receive the server response in a timely manner and eventually drop the connection.

If you are running multiple SFTPGo instances connected to the same data provider, you can choose whether to allow simultaneous execution for scheduled actions.

Some actions are not supported for some triggers, rules containing incompatible actions are skipped at runtime:

- `Filesystem events`, folder quota reset cannot be executed, we don't have a direct way to get the affected folder.
- `Provider events`, user quota reset, transfer quota reset, data retention check and filesystem actions can be executed only if  a user is updated. They will be executed for the affected user. Folder quota reset can be executed only for folders. Filesystem actions are not executed for `delete` user events because the actions is executed after the user deletion.
- `IP Blocked`, user quota reset, folder quota reset, transfer quota reset, data retention check and filesystem actions cannot be executed, we only have an IP.
- `Certificate`, user quota reset, folder quota reset, transfer quota reset, data retention check and filesystem actions cannot be executed.
- `Email with attachments` are supported for filesystem events and provider events if a user is added/updated. We need a user to get the files to attach.
- `HTTP multipart requests with files as attachments` are supported for filesystem events and provider events if a user is added/updated. We need a user to get the files to attach.
