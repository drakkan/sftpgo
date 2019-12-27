## REST API CLI client

`sftpgo_api_cli.py` is a very simple command line client for `SFTPGo` REST API written in python.

It has the following requirements:

- python3 or python2
- python [Requests](https://2.python-requests.org/en/master/ "Requests") module
- Optionally, if the python module [Pygments](http://pygments.org/ "Pygments") 1.5 or above is installed, the JSON responses will be highlighted with colors.

You can see the usage with the following command:

```
python sftpgo_api_cli.py --help
```

and

```
python sftpgo_api_cli.py [sub-command] --help
```

Basically there is a sub command for each REST API and the following global arguments:

 - `-d`, `--debug`, default disabled, print useful debug info.
 - `-b`, `--base-url`, default `http://127.0.0.1:8080`. Base URL for SFTPGo REST API
 - `-a`, `--auth-type`, HTTP auth type. Supported HTTP auth type are `basic` and `digest`. Default none
 - `-u`, `--auth-user`, user for HTTP authentication
 - `-p`, `--auth-password`, password for HTTP authentication
 - `-i`, `--insecure`, enable to ignore verifying the SSL certificate. Default disabled
 - `-t`, `--no-color`, disable color highligth for JSON responses. You need python pygments module 1.5 or above for this to work. Default disabled if pygments is found, enabled if not found. Please read the note at the end of this doc for colors in Windows command prompt.

For each subcommand `--help` shows the available arguments, try for example:

```python sftpgo_api_cli.py add_user --help```

Let's see a sample usage for each REST API.

### Add user

Command:

```
python sftpgo_api_cli.py add-user test_username --password "test_pwd" --home-dir="/tmp/test_home_dir" --uid 33 --gid 1000 --max-sessions 2 --quota-size 0 --quota-files 3 --permissions "list" "download" "upload" "delete" "rename" "create_dirs" "overwrite" --subdirs-permissions "/dir1:list,download" "/dir2:*" --upload-bandwidth 100 --download-bandwidth 60 --status 0 --expiration-date 2019-01-01
```

Output:

```json
{
  "download_bandwidth": 60,
  "expiration_date": 1546297200000,
  "gid": 1000,
  "home_dir": "/tmp/test_home_dir",
  "id": 9576,
  "last_login": 0,
  "last_quota_update": 0,
  "max_sessions": 2,
  "permissions": {
    "/": [
      "list",
      "download",
      "upload",
      "delete",
      "rename",
      "create_dirs",
      "overwrite"
    ],
    "/dir1": [
      "list",
      "download"
    ],
    "/dir2": [
      "*"
    ]
  },
  "quota_files": 3,
  "quota_size": 0,
  "status": 0,
  "uid": 33,
  "upload_bandwidth": 100,
  "used_quota_files": 0,
  "used_quota_size": 0,
  "username": "test_username"
}
```

### Update user

Command:

```
python sftpgo_api_cli.py update-user 9576 test_username --password "test_pwd" --home-dir="/tmp/test_home_dir" --uid 0 --gid 33 --max-sessions 3 --quota-size 0 --quota-files 4 --permissions "*" --subdirs-permissions "/dir1:list,download,create_symlinks" --upload-bandwidth 90 --download-bandwidth 80 --status 1 --expiration-date ""
```

Output:

```json
{
  "error": "",
  "message": "User updated",
  "status": 200
}
```

### Get user by id

Command:

```
python sftpgo_api_cli.py get-user-by-id 9576
```

Output:

```json
{
  "download_bandwidth": 80,
  "expiration_date": 0,
  "gid": 33,
  "home_dir": "/tmp/test_home_dir",
  "id": 9576,
  "last_login": 0,
  "last_quota_update": 0,
  "max_sessions": 3,
  "permissions": {
    "/": [
      "*"
    ],
    "/dir1": [
      "list",
      "download",
      "create_symlinks"
    ]
  },
  "quota_files": 4,
  "quota_size": 0,
  "status": 1,
  "uid": 0,
  "upload_bandwidth": 90,
  "used_quota_files": 0,
  "used_quota_size": 0,
  "username": "test_username"
}
```

### Get users

Command:

```
python sftpgo_api_cli.py get-users --limit 1 --offset 0 --username test_username --order DESC
```

Output:

```json
[
  {
    "download_bandwidth": 80,
    "expiration_date": 0,
    "gid": 33,
    "home_dir": "/tmp/test_home_dir",
    "id": 9576,
    "last_login": 0,
    "last_quota_update": 0,
    "max_sessions": 3,
    "permissions": {
      "/": [
        "*"
      ],
      "/dir1": [
        "list",
        "download",
        "create_symlinks"
      ]
    },
    "quota_files": 4,
    "quota_size": 0,
    "status": 1,
    "uid": 0,
    "upload_bandwidth": 90,
    "used_quota_files": 0,
    "used_quota_size": 0,
    "username": "test_username"
  }
]
```

### Get active connections

Command:

```
python sftpgo_api_cli.py get-connections
```

Output:

```json
[
  {
    "active_transfers": [
      {
        "last_activity": 1577197485561,
        "operation_type": "upload",
        "path": "/test_upload.tar.gz",
        "size": 1540096,
        "start_time": 1577197471372
      }
    ],
    "client_version": "SSH-2.0-OpenSSH_8.1",
    "connection_id": "f82cfec6a391ad673edd4ae9a144f32ccb59456139f8e1185b070134fffbab7c",
    "connection_time": 1577197433003,
    "last_activity": 1577197485561,
    "protocol": "SFTP",
    "remote_address": "127.0.0.1:43714",
    "ssh_command": "",
    "username": "test_username"
  }
]
```

### Close connection

Command:

```
python sftpgo_api_cli.py close-connection f82cfec6a391ad673edd4ae9a144f32ccb59456139f8e1185b070134fffbab7c
```

Output:

```json
{
  "error": "",
  "message": "Connection closed",
  "status": 200
}
```

### Get quota scans

Command:

```
python sftpgo_api_cli.py get-quota-scans
```

### Start quota scan

Command:

```
python sftpgo_api_cli.py start-quota-scan test_username
```

Output:

```json
{
  "status": 201,
  "message": "Scan started",
  "error": ""
}
```

### Delete user

Command:

```
python sftpgo_api_cli.py delete-user 9576
```

Output:

```json
{
  "error": "",
  "message": "User deleted",
  "status": 200
}
```

### Get version

Command:

```
python sftpgo_api_cli.py get-version
```

Output:

```json
{
  "build_date": "2019-12-24T14:17:47Z",
  "commit_hash": "f8fd5c0-dirty",
  "version": "0.9.4-dev"
}
```

### Get provider status

Command:

```
python sftpgo_api_cli.py get-provider-status
```

Output:

```json
{
  "error": "",
  "message": "Alive",
  "status": 200
}
```

### Backup data

Command:

```
python sftpgo_api_cli.py dumpdata backup.json
```

Output:

```json
{
  "error": "",
  "message": "Data saved",
  "status": 200
}
```

### Restore data

Command:

```
python sftpgo_api_cli.py loaddata /app/data/backups/backup.json --scan-quota 2
```

Output:

```json
{
  "error": "",
  "message": "Data restored",
  "status": 200
}
```

### Colors highlight for Windows command prompt

If your Windows command prompt does not recognize ANSI/VT100 escape sequences you can download [ANSICON](https://github.com/adoxa/ansicon "ANSICON") extract proper files depending on your Windows OS, and install them using `ansicon -i`.
Thats all. From now on, your Windows command prompt will be aware of ANSI colors.