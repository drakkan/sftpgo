# Bulk user update

The `bulkuserupdate` example script shows how to use the SFTPGo REST API to easily update some common parameters for multiple users while preserving the others.

The script is written in Python and has the following requirements:

- python3 or python2
- python [Requests](https://requests.readthedocs.io/en/master/) module

The provided example tries to connect to an SFTPGo instance running on `127.0.0.1:8080` using the following credentials:

- username: `admin`
- password: `password`

and it updates some fields for `user1`, `user2` and `user3`.

Please edit the script according to your needs.
