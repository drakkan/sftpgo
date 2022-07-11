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

The following placeholders are supported:

- `{{Name}}`. Username, folder name or admin username for provider actions.
- `{{Event}}`. Event name, for example `upload`, `download` for filesystem events or `add`, `update` for provider events.
- `{{Status}}`. Status for `upload`, `download` and `ssh_cmd` events. 1 means no error, 2 means a generic error occurred, 3 means quota exceeded error.
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

Event rules are based on the premise that an event occours. To each rule you can associate one or more actions.
The following trigger events are supported:

- `Filesystem events`, for example `upload`, `download` etc.
- `Provider events`, for example add/update/delete user.
- `Schedules`.

You can further restrict a rule by specifying additional conditions that must be met before the rule’s actions are taken. For example you can react to uploads only if they are performed by a particular user or using a specified protocol.

Actions are executed in a sequential order. For each action associated to a rule you can define the following settings:

- `Stop on failure`, the next action will not be executed if the current one fails.
- `Failure action`, this action will be executed only if at least another one fails.
- `Execute sync`, for upload events, you can execute the action synchronously. Executing an action synchronously means that SFTPGo will not return a result code to the client (which is waiting for it) until your action have completed its execution. If your acion takes a long time to complete this could cause a timeout on the client side, which wouldn't receive the server response in a timely manner and eventually drop the connection.

If you are running multiple SFTPGo instances connected to the same data provider, you can choose whether to allow simultaneous execution for scheduled actions.
