# Data retention hook

This hook runs after a data retention check completes if you specify `Hook` between notifications methods when you start the check.

The `data_retention_hook` can be defined as the absolute path of your program or an HTTP URL.

If the hook defines an external program it can read the following environment variable:

- `SFTPGO_DATA_RETENTION_RESULT`, it contains the data retention check result JSON serialized.

Previous global environment variables aren't cleared when the script is called.
The program must finish within 20 seconds.

If the hook defines an HTTP URL then this URL will be invoked as HTTP POST and the POST body contains the data retention check result JSON serialized.

The HTTP hook will use the global configuration for HTTP clients and will respect the retry configurations.

Here is the schema for the data retention check result:

- `username`, string
- `status`, int. 1 means success, 0 error
- `start_time`, int64. Start time as UNIX timestamp in milliseconds
- `total_deleted_files`, int. Total number of files deleted
- `total_deleted_size`, int64. Total size deleted in bytes
- `elapsed`, int64. Elapsed time in milliseconds
- `details`, list of struct with details for each checked path, each struct contains the following fields:
  - `path`, string
  - `retention`, int. Retention time in hours
  - `deleted_files`, int. Number of files deleted
  - `deleted_size`, int64. Size deleted in bytes
  - `info`, string. Informative, non fatal, message if any. For example it can indicates that the check was skipped because the user doesn't have the required permissions on this path
  - `error`, string. Error message if any
