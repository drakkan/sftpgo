## REST API CLI client

`sftpgo_api_cli.py` is a very simple command line client for `SFTPGo` REST API written in python. It requires python3 and the python HTTP library [Requests](https://2.python-requests.org/en/master/ "Requests") to run.

You can see the usage with the following command:

```
python sftpgo_api_cli.py --help
```

Basically there is a subcommand for each REST API and a two global arguments:

 - `debug`, default disabled, print useful debug info.
 - `base_url`, default `http://127.0.0.1:8080`. Base URL for SFTPGo REST API
 - `auth_type` supported auth type are `basic` and `digest`. Default none
 - `auth_user`
 - `auth_password`
 - `verify`, disable to ignore verifying the SSL certificate. Default enabled

For each subcommand `--help` shows the required arguments, try for example:

```python sftpgo_api_cli.py add_user --help```

Let's see a sample usage for each REST API.

### Add user

Command:

```
python sftpgo_api_cli.py add_user test_username --password "test_pwd" --home_dir="/tmp/test_home_dir" --uid 33 --gid 1000 --max_sessions 2 --quota_size 0 --quota_files 3 --permissions "list" "download" "upload" "delete" "rename" "create_dirs" --upload_bandwidth 100 --download_bandwidth 60
```

Output:

```json
{
  "id": 5140,
  "username": "test_username",
  "home_dir": "/tmp/test_home_dir",
  "uid": 33,
  "gid": 1000,
  "max_sessions": 2,
  "quota_size": 0,
  "quota_files": 3,
  "permissions": [
    "list",
    "download",
    "upload",
    "delete",
    "rename",
    "create_dirs"
  ],
  "used_quota_size": 0,
  "used_quota_files": 0,
  "last_quota_update": 0,
  "upload_bandwidth": 100,
  "download_bandwidth": 60
}
```

### Update user

Command:

```
python sftpgo_api_cli.py update_user 5140 test_username --password "test_pwd" --home_dir="/tmp/test_home_dir" --uid 0 --gid 33 --max_sessions 2 --quota_size 0 --quota_files 4 --permissions "*" --upload_bandwidth 90 --download_bandwidth 80
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
python sftpgo_api_cli.py get_user_by_id 5140
```

Output:

```json
{
  "id": 5140,
  "username": "test_username",
  "home_dir": "/tmp/test_home_dir",
  "uid": 0,
  "gid": 33,
  "max_sessions": 2,
  "quota_size": 0,
  "quota_files": 4,
  "permissions": [
    "*"
  ],
  "used_quota_size": 0,
  "used_quota_files": 0,
  "last_quota_update": 0,
  "upload_bandwidth": 90,
  "download_bandwidth": 80
}
```

### Get users

Command:

```
python sftpgo_api_cli.py get_users --limit 1 --offset 0 --username test_username --order DESC
```

Output:

```json
[
  {
    "id": 5140,
    "username": "test_username",
    "home_dir": "/tmp/test_home_dir",
    "uid": 0,
    "gid": 33,
    "max_sessions": 2,
    "quota_size": 0,
    "quota_files": 4,
    "permissions": [
      "*"
    ],
    "used_quota_size": 0,
    "used_quota_files": 0,
    "last_quota_update": 0,
    "upload_bandwidth": 90,
    "download_bandwidth": 80
  }
]
```

### Get SFTP connections

Command:

```
python sftpgo_api_cli.py get_sftp_connections
```

Output:

```json
[
  {
    "username": "test_username",
    "connection_id": "76a11b22260ee4249328df28bef34dc64c70f7c097db52159fc24049eeb0e32c",
    "client_version": "SSH-2.0-OpenSSH_8.0",
    "remote_address": "127.0.0.1:41622",
    "connection_time": 1564696137971,
    "last_activity": 1564696159605,
    "active_transfers": [
      {
        "operation_type": "upload",
        "start_time": 1564696149783,
        "size": 1146880,
        "last_activity": 1564696159605
      }
    ]
  }
]
```

### Close SFTP connection

Command:

```
python sftpgo_api_cli.py close_sftp_connection 76a11b22260ee4249328df28bef34dc64c70f7c097db52159fc24049eeb0e32c
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
python sftpgo_api_cli.py get_quota_scans
```

### Start quota scan

Command:

```
python sftpgo_api_cli.py start_quota_scan test_username
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
python sftpgo_api_cli.py delete_user 5140
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
python sftpgo_api_cli.py get_version
```

Output:

```json
{
  "version": "0.9.0-dev",
  "build_date": "2019-08-08T08:11:34Z",
  "commit_hash": "4f4489d-dirty"
}
```