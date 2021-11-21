# REST API CLI client

:warning: This sample client is deprecated and it will work only with API V1 (SFTPGo <= 1.2.2). You can easily build your own client from the [OpenAPI](../../openapi/openapi.yaml) schema or use [Swagger UI](https://github.com/swagger-api/swagger-ui).

`sftpgo_api_cli` is a very simple command line client for `SFTPGo` REST API written in python.

It has the following requirements:

- python3 or python2
- python [Requests](https://2.python-requests.org/en/master/ "Requests") module
- Optionally, if the python module [Pygments](http://pygments.org/ "Pygments") 1.5 or above is installed, the JSON responses will be highlighted with colors.

You can see the usage with the following command:

```console
python sftpgo_api_cli --help
```

and

```console
python sftpgo_api_cli [sub-command] --help
```

Basically there is a sub command for each REST API and the following global arguments:

- `-d`, `--debug`, default disabled, print useful debug info.
- `-b`, `--base-url`, default `http://127.0.0.1:8080`. Base URL for SFTPGo REST API
- `-a`, `--auth-type`, HTTP auth type. Supported HTTP auth type are `basic` and `digest`. Default none
- `-u`, `--auth-user`, user for HTTP authentication
- `-p`, `--auth-password`, password for HTTP authentication
- `-i`, `--insecure`, enable to ignore verifying the SSL certificate. Default disabled
- `-t`, `--no-color`, disable color highligth for JSON responses. You need python pygments module 1.5 or above for this to work. Default disabled if pygments is found and you aren't on Windows, otherwise enabled.
- `-c`, `--color`, enable color highligth for JSON responses. You need python pygments module 1.5 or above for this to work. Default enabled if `pygments` is found and you aren't on Windows, otherwise disabled. Please read the note at the end of this doc for colors in Windows command prompt.

For each subcommand `--help` shows the available arguments, try for example:

```python sftpgo_api_cli add-user --help```

Additionally it can convert users to the SFTPGo format from some supported users stores

Let's see a sample usage for each REST API.

## Add user

Command:

```console
python sftpgo_api_cli add-user test_username --password "test_pwd" --home-dir="/tmp/test_home_dir" --uid 33 --gid 1000 --max-sessions 2 --quota-size 0 --quota-files 3 --permissions "list" "download" "upload" "delete" "rename" "create_dirs" "overwrite" --subdirs-permissions "/dir1::list,download" "/dir2::*" --upload-bandwidth 100 --download-bandwidth 60 --status 0 --expiration-date 2019-01-01 --allowed-ip "192.168.1.1/32" --fs S3 --s3-bucket test --s3-region eu-west-1 --s3-access-key accesskey --s3-access-secret secret --s3-endpoint "http://127.0.0.1:9000" --s3-storage-class Standard --s3-key-prefix "vfolder/" --s3-upload-part-size 10 --s3-upload-concurrency 4 --denied-login-methods "password" "keyboard-interactive" --allowed-patterns "/dir1::*.jpg,*.png" "/dir2::*.rar,*.png" --denied-patterns "/dir3::*.zip,*.rar" --denied-protocols DAV FTP --additional-info "sample info"
```

Output:

```json
{
  "additional_info": "sample info",
  "download_bandwidth": 60,
  "expiration_date": 1546297200000,
  "filesystem": {
    "azblobconfig": {
      "account_key": {}
    },
    "cryptconfig": {
      "passphrase": {}
    },
    "gcsconfig": {
      "credentials": {}
    },
    "provider": 1,
    "s3config": {
      "access_key": "accesskey",
      "access_secret": {
        "payload": "ALVIG4egZxRjKH8/8NsJViA7EH5MqsweqmwLhGj4M4AGYgMM2ygF7kbCw+R5aQ==",
        "status": "Secretbox"
      },
      "bucket": "test",
      "endpoint": "http://127.0.0.1:9000",
      "key_prefix": "vfolder/",
      "region": "eu-west-1",
      "storage_class": "Standard",
      "upload_concurrency": 4,
      "upload_part_size": 10
    },
    "sftpconfig": {
      "password": {},
      "private_key": {}
    }
  },
  "filters": {
    "allowed_ip": [
      "192.168.1.1/32"
    ],
    "denied_login_methods": [
      "password",
      "keyboard-interactive"
    ],
    "denied_protocols": [
      "DAV",
      "FTP"
    ],
    "file_patterns": [
      {
        "allowed_patterns": [
          "*.jpg",
          "*.png"
        ],
        "path": "/dir1"
      },
      {
        "allowed_patterns": [
          "*.rar",
          "*.png"
        ],
        "path": "/dir2"
      },
      {
        "denied_patterns": [
          "*.zip",
          "*.rar"
        ],
        "path": "/dir3"
      }
    ]
  },
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

## Update user

Command:

```console
python sftpgo_api_cli update-user 9576 test_username --password "test_pwd" --home-dir="/tmp/test_home_dir" --uid 0 --gid 33 --max-sessions 3 --quota-size 0 --quota-files 4 --permissions "*" --subdirs-permissions "/dir1::list,download,create_symlinks" --upload-bandwidth 90 --download-bandwidth 80 --status 1 --expiration-date "" --allowed-ip "" --denied-ip "192.168.1.0/24" --denied-login-methods "" --fs local --virtual-folders "/vdir1::/tmp/mapped1::-1::-1" "/vdir2::/tmp/mapped2::100::104857600" --allowed-patterns "" --denied-patterns "" --max-upload-file-size 104857600 --denied-protocols ""
```

Output:

```json
{
  "error": "",
  "message": "User updated",
  "status": 200
}
```

You can set the argument `--disconnect` to `1` to disconnect the user, if connected, after a successful update and so force it to login again and to use the new configuration. If this parameter is not specified the user will continue to use the old configuration as long as he is logged in.

## Get user by id

Command:

```console
python sftpgo_api_cli get-user-by-id 9576
```

Output:

```json
{
  "download_bandwidth": 80,
  "expiration_date": 0,
  "filesystem": {
    "azblobconfig": {
      "account_key": {}
    },
    "cryptconfig": {
      "passphrase": {}
    },
    "gcsconfig": {
      "credentials": {}
    },
    "provider": 0,
    "s3config": {
      "access_secret": {}
    },
    "sftpconfig": {
      "password": {},
      "private_key": {}
    }
  },
  "filters": {
    "denied_ip": [
      "192.168.1.0/24"
    ],
    "max_upload_file_size": 104857600
  },
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
  "username": "test_username",
  "virtual_folders": [
    {
      "id": 1,
      "last_quota_update": 0,
      "mapped_path": "/tmp/mapped1",
      "quota_files": -1,
      "quota_size": -1,
      "used_quota_files": 0,
      "used_quota_size": 0,
      "virtual_path": "/vdir1"
    },
    {
      "id": 2,
      "last_quota_update": 0,
      "mapped_path": "/tmp/mapped2",
      "quota_files": 100,
      "quota_size": 104857600,
      "used_quota_files": 0,
      "used_quota_size": 0,
      "virtual_path": "/vdir2"
    }
  ]
}
```

## Get users

Command:

```console
python sftpgo_api_cli get-users --limit 1 --offset 0 --username test_username --order DESC
```

Output:

```json
[
  {
    "download_bandwidth": 80,
    "expiration_date": 0,
    "filesystem": {
      "azblobconfig": {
        "account_key": {}
      },
      "cryptconfig": {
        "passphrase": {}
      },
      "gcsconfig": {
        "credentials": {}
      },
      "provider": 0,
      "s3config": {
        "access_secret": {}
      },
      "sftpconfig": {
        "password": {},
        "private_key": {}
      }
    },
    "filters": {
      "denied_ip": [
        "192.168.1.0/24"
      ],
      "max_upload_file_size": 104857600
    },
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
    "username": "test_username",
    "virtual_folders": [
      {
        "exclude_from_quota": false,
        "mapped_path": "/tmp/mapped1",
        "virtual_path": "/vdir1"
      },
      {
        "exclude_from_quota": true,
        "mapped_path": "/tmp/mapped2",
        "virtual_path": "/vdir2"
      }
    ]
  }
]
```

## Get active connections

Command:

```console
python sftpgo_api_cli get-connections
```

Output:

```json
[
  {
    "active_transfers": [
      {
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
    "username": "test_username"
  }
]
```

## Get folders

Command:

```console
python sftpgo_api_cli get-folders --limit 1 --offset 0 --folder-path /tmp/mapped1 --order DESC
```

Output:

```json
[
  {
    "id": 1,
    "last_quota_update": 1591563422870,
    "mapped_path": "/tmp/mapped1",
    "used_quota_files": 1,
    "used_quota_size": 13313790,
    "users": [
      "test_username"
    ]
  }
]
```

## Add folder

```console
python sftpgo_api_cli add-folder /tmp/mapped_folder
```

Output:

```json
{
  "id": 4,
  "last_quota_update": 0,
  "mapped_path": "/tmp/mapped_folder",
  "used_quota_files": 0,
  "used_quota_size": 0
}
```

## Close connection

Command:

```console
python sftpgo_api_cli close-connection f82cfec6a391ad673edd4ae9a144f32ccb59456139f8e1185b070134fffbab7c
```

Output:

```json
{
  "error": "",
  "message": "Connection closed",
  "status": 200
}
```

## Get quota scans

Command:

```console
python sftpgo_api_cli get-quota-scans
```

## Start quota scan

Command:

```console
python sftpgo_api_cli start-quota-scan test_username
```

Output:

```json
{
  "status": 201,
  "message": "Scan started",
  "error": ""
}
```

## Get folder quota scans

Command:

```console
python sftpgo_api_cli get-folders-quota-scans
```

## Start folder quota scan

Command:

```console
python sftpgo_api_cli start-folder-quota-scan /tmp/mapped_folder
```

Output:

```json
{
  "status": 201,
  "message": "Scan started",
  "error": ""
}
```

## Update quota usage

Command:

```console
python sftpgo_api_cli -d update-quota-usage a -S 123 -F 1 -M reset
```

Output:

```json
{
  "error": "",
  "message": "Quota updated",
  "status": 200
}
```

## Update folder quota usage

Command:

```console
python sftpgo_api_cli -d update-quota-usage /tmp/mapped_folder -S 123 -F 1 -M add
```

Output:

```json
{
  "error": "",
  "message": "Quota updated",
  "status": 200
}
```

## Delete user

Command:

```console
python sftpgo_api_cli delete-user 9576
```

Output:

```json
{
  "error": "",
  "message": "User deleted",
  "status": 200
}
```

## Delete folder

```console
python sftpgo_api_cli delete-folder /tmp/mapped_folder
```

Output:

```json
{
  "error": "",
  "message": "Folder deleted",
  "status": 200
}
```

## Get version

Command:

```console
python sftpgo_api_cli get-version
```

Output:

```json
{
  "build_date": "2019-12-24T14:17:47Z",
  "commit_hash": "f8fd5c0-dirty",
  "version": "0.9.4-dev"
}
```

## Get provider status

Command:

```console
python sftpgo_api_cli get-provider-status
```

Output:

```json
{
  "error": "",
  "message": "Alive",
  "status": 200
}
```

## Backup data

Command:

```console
python sftpgo_api_cli dumpdata backup.json --indent 1
```

Output:

```json
{
  "error": "",
  "message": "Data saved",
  "status": 200
}
```

## Restore data

Command:

```console
python sftpgo_api_cli loaddata /app/data/backups/backup.json --scan-quota 2 --mode 0
```

Output:

```json
{
  "error": "",
  "message": "Data restored",
  "status": 200
}
```

## Convert users from other stores

You can convert users to the SFTPGo format from the following users stores:

- Linux users stored in `shadow`/`passwd` files
- Pure-FTPd virtual users generated using `pure-pw` CLI
- ProFTPD users generated using `ftpasswd` CLI

For details give a look at the `convert-users` subcommand usage:

```console
python sftpgo_api_cli convert-users --help
```

Let's see some examples:

```console
python sftpgo_api_cli convert-users "" unix-passwd unix_users.json --min-uid 500 --force-uid 1000 --force-gid 1000
```

```console
python sftpgo_api_cli convert-users pureftpd.passwd pure-ftpd pure_users.json --usernames "user1" "user2"
```

```console
python sftpgo_api_cli convert-users proftpd.passwd proftpd pro_users.json
```

The json file generated using the `convert-users` subcommand can be used as input for the `loaddata` subcommand.

Please note that when importing Linux/Unix users the input file is not required: `/etc/passwd` and `/etc/shadow` are automatically parsed. `/etc/shadow` read permission is is typically granted to the `root` user, so you need to execute the `convert-users` subcommand as `root`.

## Colors highlight for Windows command prompt

If your Windows command prompt does not recognize ANSI/VT100 escape sequences you can download [ANSICON](https://github.com/adoxa/ansicon "ANSICON") extract proper files depending on your Windows OS, and install them using `ansicon -i`.
Thats all. From now on, your Windows command prompt will be aware of ANSI colors.
