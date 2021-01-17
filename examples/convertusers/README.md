# Import users from other stores

`convertusers` is a very simple command line client, written in python, to import users from other stores. It requires `python3` or `python2`.

Here is the usage:

```console
usage: convertusers [-h] [--min-uid MIN_UID] [--max-uid MAX_UID] [--usernames USERNAMES [USERNAMES ...]]
                    [--force-uid FORCE_UID] [--force-gid FORCE_GID]
                    input_file {unix-passwd,pure-ftpd,proftpd} output_file

Convert users to a JSON format suitable to use with loadddata

positional arguments:
  input_file
  {unix-passwd,pure-ftpd,proftpd}
                        To import from unix-passwd format you need the permission to read /etc/shadow that is typically
                        granted to the root user only
  output_file

optional arguments:
  -h, --help            show this help message and exit
  --min-uid MIN_UID     if >= 0 only import users with UID greater or equal to this value. Default: -1
  --max-uid MAX_UID     if >= 0 only import users with UID lesser or equal to this value. Default: -1
  --usernames USERNAMES [USERNAMES ...]
                        Only import users with these usernames. Default: []
  --force-uid FORCE_UID
                        if >= 0 the imported users will have this UID in SFTPGo. Default: -1
  --force-gid FORCE_GID
                        if >= 0 the imported users will have this GID in SFTPGo. Default: -1
```

Let's see some examples:

```console
python convertusers "" unix-passwd unix_users.json --min-uid 500 --force-uid 1000 --force-gid 1000
```

```console
python convertusers pureftpd.passwd pure-ftpd pure_users.json --usernames "user1" "user2"
```

```console
python convertusers proftpd.passwd proftpd pro_users.json
```

The generated json file can be used as input for the `loaddata` REST API.

Please note that when importing Linux/Unix users the input file is not required: `/etc/passwd` and `/etc/shadow` are automatically parsed. `/etc/shadow` read permission is typically granted to the `root` user only, so you need to execute `convertusers` as `root`.
