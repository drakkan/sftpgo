# Account's configuration properties

For each account, the following properties can be configured:

- `username`
- `password` used for password authentication. For users created using SFTPGo REST API, if the password has no known hashing algo prefix, it will be stored using argon2id. SFTPGo supports checking passwords stored with bcrypt, pbkdf2, md5crypt and sha512crypt too. For pbkdf2 the supported format is `$<algo>$<iterations>$<salt>$<hashed pwd base64 encoded>`, where algo is `pbkdf2-sha1` or `pbkdf2-sha256` or `pbkdf2-sha512` or `$pbkdf2-b64salt-sha256$`. For example the `pbkdf2-sha256` of the word `password` using 150000 iterations and `E86a9YMX3zC7` as salt must be stored as `$pbkdf2-sha256$150000$E86a9YMX3zC7$R5J62hsSq+pYw00hLLPKBbcGXmq7fj5+/M0IFoYtZbo=`. In pbkdf2 variant with `b64salt` the salt is base64 encoded. For bcrypt the format must be the one supported by golang's [crypto/bcrypt](https://godoc.org/golang.org/x/crypto/bcrypt) package, for example the password `secret` with cost `14` must be stored as `$2a$14$ajq8Q7fbtFRQvXpdCq7Jcuy.Rx1h/L4J60Otx.gyNLbAYctGMJ9tK`. For md5crypt and sha512crypt we support the format used in `/etc/shadow` with the `$1$` and `$6$` prefix, this is useful if you are migrating from Unix system user accounts. We support Apache md5crypt (`$apr1$` prefix) too. Using the REST API you can send a password hashed as bcrypt, pbkdf2, md5crypt or sha512crypt and it will be stored as is.
- `public_keys` array of public keys. At least one public key or the password is mandatory.
- `status` 1 means "active", 0 "inactive". An inactive account cannot login.
- `expiration_date` expiration date as unix timestamp in milliseconds. An expired account cannot login. 0 means no expiration.
- `home_dir` the user cannot upload or download files outside this directory. Must be an absolute path. A local home directory is required for Cloud Storage Backends too: in this case it will store temporary files.
- `virtual_folders` list of mappings between virtual SFTP/SCP paths and local filesystem paths outside the user home directory. More information can be found [here](./virtual-folders.md)
- `uid`, `gid`. If SFTPGo runs as root system user then the created files and directories will be assigned to this system uid/gid. Ignored on windows or if SFTPGo runs as non root user: in this case files and directories for all SFTP users will be owned by the system user that runs SFTPGo.
- `max_sessions` maximum concurrent sessions. 0 means unlimited.
- `quota_size` maximum size allowed as bytes. 0 means unlimited.
- `quota_files` maximum number of files allowed. 0 means unlimited.
- `permissions` for SFTP paths. The following per directory permissions are supported:
  - `*` all permissions are granted
  - `list` list items is allowed
  - `download` download files is allowed
  - `upload` upload files is allowed
  - `overwrite` overwrite an existing file, while uploading, is allowed. `upload` permission is required to allow file overwrite
  - `delete` delete files or directories is allowed
  - `rename` rename a file or a directory is allowed if this permission is granted on source and target path. You can enable rename in a more controlled way granting `delete` permission on source directory and `upload`/`create_dirs`/`create_symlinks` permissions on target directory
  - `create_dirs` create directories is allowed
  - `create_symlinks` create symbolic links is allowed
  - `chmod` changing file or directory permissions is allowed. On Windows, only the 0200 bit (owner writable) of mode is used; it controls whether the file's read-only attribute is set or cleared. The other bits are currently unused. Use mode 0400 for a read-only file and 0600 for a readable+writable file.
  - `chown` changing file or directory owner and group is allowed. Changing owner and group is not supported on Windows.
  - `chtimes` changing file or directory access and modification time is allowed
- `upload_bandwidth` maximum upload bandwidth as KB/s, 0 means unlimited.
- `download_bandwidth` maximum download bandwidth as KB/s, 0 means unlimited.
- `last_login` last user login as unix timestamp in milliseconds. It is saved at most once every 10 minutes
- `allowed_ip`, List of IP/Mask allowed to login. Any IP address not contained in this list cannot login. IP/Mask must be in CIDR notation as defined in RFC 4632 and RFC 4291, for example "192.0.2.0/24" or "2001:db8::/32"
- `denied_ip`, List of IP/Mask not allowed to login. If an IP address is both allowed and denied then login will be denied
- `max_upload_file_size`, max allowed size, as bytes, for a single file upload. The upload will be aborted if/when the size of the file being sent exceeds this limit. 0 means unlimited. This restriction does not apply for SSH system commands such as `git` and `rsync`
- `denied_login_methods`, List of login methods not allowed. To enable multi-step authentication you have to allow only multi-step login methods. If password login method is denied or no password is set then FTP and WebDAV users cannot login. The following login methods are supported:
  - `publickey`
  - `password`
  - `keyboard-interactive`
  - `publickey+password`
  - `publickey+keyboard-interactive`
- `denied_protocols`, list of protocols not allowed. The following protocols are supported:
  - `SSH`
  - `FTP`
  - `DAV`
- `file_extensions`, list of struct. Deprecated, please use `file_patterns`. These restrictions do not apply to files listing for performance reasons, so a denied file cannot be downloaded/overwritten/renamed but it will still be in the list of files. Please note that these restrictions can be easily bypassed. Each struct contains the following fields:
  - `allowed_extensions`, list of, case insensitive, allowed file extensions. Shell like expansion is not supported so you have to specify `.jpg` and not `*.jpg`. Any file that does not end with this suffix will be denied
  - `denied_extensions`, list of, case insensitive, denied file extensions. Denied file extensions are evaluated before the allowed ones
  - `path`, exposed virtual path, if no other specific filter is defined, the filter apply for sub directories too. For example if filters are defined for the paths `/` and `/sub` then the filters for `/` are applied for any file outside the `/sub` directory
- `file_patterns`, list of struct. These restrictions do not apply to files listing for performance reasons, so a denied file cannot be downloaded/overwritten/renamed but it will still be in the list of files. Please note that these restrictions can be easily bypassed. For syntax details take a look [here](https://golang.org/pkg/path/#Match). Each struct contains the following fields:
  - `allowed_patterns`, list of, case insensitive, allowed file patterns. Examples: `*.jpg`, `a*b?.png`. Any non matching file will be denied
  - `denied_patterns`, list of, case insensitive, denied file patterns. Denied file patterns are evaluated before the allowed ones
  - `path`, exposed virtual path, if no other specific filter is defined, the filter apply for sub directories too. For example if filters are defined for the paths `/` and `/sub` then the filters for `/` are applied for any file outside the `/sub` directory
- `fs_provider`, filesystem to serve via SFTP. Local filesystem (0), S3 Compatible Object Storage (1), Google Cloud Storage (2), Azure Blob Storage (3) and encrypted local filesystem (4) are supported
- `s3_bucket`, required for S3 filesystem
- `s3_region`, required for S3 filesystem. Must match the region for your bucket. You can find here the list of available [AWS regions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions). For example if your bucket is at `Frankfurt` you have to set the region to `eu-central-1`
- `s3_access_key`
- `s3_access_secret`, if provided it is stored encrypted based on kms configuration. You can leave access key and access secret blank to use credentials from environment
- `s3_endpoint`, specifies a S3 endpoint (server) different from AWS. It is not required if you are connecting to AWS
- `s3_storage_class`, leave blank to use the default or specify a valid AWS [storage class](https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-class-intro.html)
- `s3_key_prefix`, allows to restrict access to the folder identified by this prefix and its contents
- `s3_upload_part_size`, the buffer size for multipart uploads (MB). Zero means the default (5 MB). Minimum is 5
- `s3_upload_concurrency` how many parts are uploaded in parallel
- `gcs_bucket`, required for GCS filesystem
- `gcs_credentials`, Google Cloud Storage JSON credentials base64 encoded. Credentials are stored encrypted based on kms configuration
- `gcs_automatic_credentials`, integer. Set to 1 to use Application Default Credentials strategy or set to 0 to use explicit credentials via `gcs_credentials`
- `gcs_storage_class`
- `gcs_key_prefix`, allows to restrict access to the folder identified by this prefix and its contents
- `az_container`, Azure Blob Storage container
- `az_account_name`, Azure account name. leave blank to use SAS URL
- `az_account_key`, Azure account key. leave blank to use SAS URL. If provided it is stored encrypted based on kms configuration
- `az_sas_url`, Azure shared access signature URL
- `az_endpoint`, Default is "blob.core.windows.net". If you use the emulator the endpoint must include the protocol, for example "http://127.0.0.1:10000"
- `az_upload_part_size`, the buffer size for multipart uploads (MB). Zero means the default (4 MB)
- `az_upload_concurrency`,  how many parts are uploaded in parallel. Zero means the default (2)
- `az_key_prefix`,  allows to restrict access to the folder identified by this prefix and its contents
- `az_use_emulator`, boolean
- `crypt_passphrase`, passphrase to use for local encryption
- `additional_info`, string. Free text field

These properties are stored inside the data provider.

If you want to use your existing accounts, you have these options:

- you can import your users inside SFTPGo. Take a look at [sftpgo_api_cli](../examples/rest-api-cli#convert-users-from-other-stores "SFTPGo API CLI example"), it can convert and import users from Linux system users and Pure-FTPd/ProFTPD virtual users
- you can use an external authentication program

Please take a look at the [OpenAPI schema](../httpd/schema/openapi.yaml) for the exact definitions of user and folder fields.
If you need an example you can export a dump using the REST API CLI client or by invoking the `dumpdata` endpoint directly, for example:

```shell
curl "http://127.0.0.1:8080/api/v1/dumpdata?output_file=dump.json&indent=1"
```

the dump is a JSON with users and folder.
