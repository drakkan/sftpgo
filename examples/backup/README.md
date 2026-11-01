# Data Backup

:warning: Since v2.4.0 you can use the EventManager to schedule backups.

The `backup` example script shows how to use the GoNAS REST API to backup your data.

The script is written in Python and has the following requirements:

- python3 or python2
- python [Requests](https://requests.readthedocs.io/en/master/) module

The provided example tries to connect to an GoNAS instance running on `127.0.0.1:8080` using the following credentials:

- username: `admin`
- password: `password`

and, if you execute it daily, it saves a different backup file for each day of the week. The backups will be saved within the configured `backups_path`.

Please edit the script according to your needs.
