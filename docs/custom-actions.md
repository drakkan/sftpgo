# Custom Actions

The `actions` struct inside the `common` configuration section allows to configure the actions for file operations and SSH commands.
The `hook` can be defined as the absolute path of your program or an HTTP URL.

The following `actions` are supported:

- `download`
- `pre-download`
- `upload`
- `pre-upload`
- `delete`
- `pre-delete`
- `rename`
- `ssh_cmd`

The `upload` condition includes both uploads to new files and overwrite of existing files. If an upload is aborted for quota limits SFTPGo tries to remove the partial file, so if the notification reports a zero size file and a quota exceeded error the file has been deleted. The `ssh_cmd` condition will be triggered after a command is successfully executed via SSH. `scp` will trigger the `download` and `upload` conditions and not `ssh_cmd`.

The notification will indicate if an error is detected and so, for example, a partial file is uploaded.

The `pre-delete` action, if defined, will be called just before files deletion. If the external command completes with a zero exit status or the HTTP notification response code is `200` then SFTPGo will assume that the file was already deleted/moved and so it will not try to remove the file and it will not execute the hook defined for the `delete` action.

The `pre-download` and `pre-upload` actions, will be called before downloads and uploads. If the external command completes with a zero exit status or the HTTP notification response code is `200` then SFTPGo allows the operation, otherwise the client will get a permission denied error.

If the `hook` defines a path to an external program, then this program is invoked with the following arguments:

- `action`, string, supported action
- `username`
- `path` is the full filesystem path, can be empty for some ssh commands
- `target_path`, non-empty for `rename` action and for `sftpgo-copy` SSH command
- `ssh_cmd`, non-empty for `ssh_cmd` action

The external program can also read the following environment variables:

- `SFTPGO_ACTION`
- `SFTPGO_ACTION_USERNAME`
- `SFTPGO_ACTION_PATH`
- `SFTPGO_ACTION_TARGET`, non-empty for `rename` `SFTPGO_ACTION`
- `SFTPGO_ACTION_SSH_CMD`, non-empty for `ssh_cmd` `SFTPGO_ACTION`
- `SFTPGO_ACTION_FILE_SIZE`, non-zero for `pre-upload`,`upload`, `download` and `delete` actions if the file size is greater than `0`
- `SFTPGO_ACTION_FS_PROVIDER`, `0` for local filesystem, `1` for S3 backend, `2` for Google Cloud Storage (GCS) backend, `3` for Azure Blob Storage backend, `4` for local encrypted backend, `5` for SFTP backend
- `SFTPGO_ACTION_BUCKET`, non-empty for S3, GCS and Azure backends
- `SFTPGO_ACTION_ENDPOINT`, non-empty for S3, SFTP and Azure backend if configured. For Azure this is the endpoint, if configured
- `SFTPGO_ACTION_STATUS`, integer. Status for `upload`, `download` and `ssh_cmd` actions. 0 means a generic error occurred. 1 means no error, 2 means quota exceeded error
- `SFTPGO_ACTION_PROTOCOL`, string. Possible values are `SSH`, `SFTP`, `SCP`, `FTP`, `DAV`, `HTTP`
- `SFTPGO_ACTION_OPEN_FLAGS`, integer. File open flags, can be non-zero for `pre-upload` action. If `SFTPGO_ACTION_FILE_SIZE` is greater than zero and `SFTPGO_ACTION_OPEN_FLAGS&512 == 0` the target file will not be truncated

Previous global environment variables aren't cleared when the script is called.
The program must finish within 30 seconds.

If the `hook` defines an HTTP URL then this URL will be invoked as HTTP POST. The request body will contain a JSON serialized struct with the following fields:

- `action`
- `username`
- `path`
- `target_path`, included for `rename` action
- `ssh_cmd`, included for `ssh_cmd` action
- `file_size`, included for `pre-upload`, `upload`, `download`, `delete` actions if the file size is greater than `0`
- `fs_provider`, `0` for local filesystem, `1` for S3 backend, `2` for Google Cloud Storage (GCS) backend, `3` for Azure Blob Storage backend, `4` for local encrypted backend, `5` for SFTP backend
- `bucket`, inlcuded for S3, GCS and Azure backends
- `endpoint`, included for S3, SFTP and Azure backend if configured. For Azure this is the endpoint, if configured
- `status`, integer. Status for `upload`, `download` and `ssh_cmd` actions. 0 means a generic error occurred. 1 means no error, 2 means quota exceeded error
- `protocol`, string. Possible values are `SSH`, `SFTP`, `SCP`, `FTP`, `DAV`, `HTTP`
- `open_flags`, integer. File open flags, can be non-zero for `pre-upload` action. If `file_size` is greater than zero and `file_size&512 == 0` the target file will not be truncated

The HTTP hook will use the global configuration for HTTP clients and will respect the retry configurations.

The `pre-*` actions are always executed synchronously while the other ones are asynchronous. You can specify the actions to run synchronously via the `execute_sync` configuration key. Executing an action synchronously means that SFTPGo will not return a result code to the client (which is waiting for it) until your hook have completed its execution. If your hook takes a long time to complete this could cause a timeout on the client side, which wouldn't receive the server response in a timely manner and eventually drop the connection.

The `actions` struct inside the `data_provider` configuration section allows you to configure actions on user add, update, delete.

Actions will not be fired for internal updates, such as the last login or the user quota fields, or after external authentication.

If the `hook` defines a path to an external program, then this program is invoked with the following arguments:

- `action`, string, possible values are: `add`, `update`, `delete`
- `username`
- `ID`
- `status`
- `expiration_date`
- `home_dir`
- `uid`
- `gid`

The external program can also read the following environment variables:

- `SFTPGO_USER_ACTION`
- `SFTPGO_USER`, user serialized as JSON with sensitive fields removed

Previous global environment variables aren't cleared when the script is called.
The program must finish within 15 seconds.

If the `hook` defines an HTTP URL then this URL will be invoked as HTTP POST. The action is added to the query string, for example `<hook>?action=update`, and the user is sent serialized as JSON inside the POST body with sensitive fields removed.

The HTTP hook will use the global configuration for HTTP clients and will respect the retry configurations.

The structure for SFTPGo users can be found within the [OpenAPI schema](../httpd/schema/openapi.yaml).
