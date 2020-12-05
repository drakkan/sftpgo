# Portable mode

SFTPGo allows to share a single directory on demand using the `portable` subcommand:

```console
sftpgo portable --help
To serve the current working directory with auto generated credentials simply
use:

$ sftpgo portable

Please take a look at the usage below to customize the serving parameters

Usage:
  sftpgo portable [flags]

Flags:
  -C, --advertise-credentials           If the SFTP/FTP service is
                                        advertised via multicast DNS, this
                                        flag allows to put username/password
                                        inside the advertised TXT record
  -S, --advertise-service               Advertise configured services using
                                        multicast DNS
      --allowed-patterns stringArray    Allowed file patterns case insensitive.
                                        The format is:
                                        /dir::pattern1,pattern2.
                                        For example: "/somedir::*.jpg,a*b?.png"
      --az-access-tier string           Leave empty to use the default
                                        container setting
      --az-account-key string
      --az-account-name string
      --az-container string
      --az-endpoint string              Leave empty to use the default:
                                        "blob.core.windows.net"
      --az-key-prefix string            Allows to restrict access to the
                                        virtual folder identified by this
                                        prefix and its contents
      --az-sas-url string               Shared access signature URL
      --az-upload-concurrency int       How many parts are uploaded in
                                        parallel (default 2)
      --az-upload-part-size int         The buffer size for multipart uploads
                                        (MB) (default 4)
      --az-use-emulator
      --crypto-passphrase string        Passphrase for encryption/decryption
      --denied-patterns stringArray     Denied file patterns case insensitive.
                                        The format is:
                                        /dir::pattern1,pattern2.
                                        For example: "/somedir::*.jpg,a*b?.png"
  -d, --directory string                Path to the directory to serve.
                                        This can be an absolute path or a path
                                        relative to the current directory
                                         (default ".")
  -f, --fs-provider int                 0 => local filesystem
                                        1 => AWS S3 compatible
                                        2 => Google Cloud Storage
                                        3 => Azure Blob Storage
                                        4 => Encrypted local filesystem
      --ftpd-cert string                Path to the certificate file for FTPS
      --ftpd-key string                 Path to the key file for FTPS
      --ftpd-port int                   0 means a random unprivileged port,
                                        < 0 disabled (default -1)
      --gcs-automatic-credentials int   0 means explicit credentials using
                                        a JSON credentials file, 1 automatic
                                         (default 1)
      --gcs-bucket string
      --gcs-credentials-file string     Google Cloud Storage JSON credentials
                                        file
      --gcs-key-prefix string           Allows to restrict access to the
                                        virtual folder identified by this
                                        prefix and its contents
      --gcs-storage-class string
  -h, --help                            help for portable
  -l, --log-file-path string            Leave empty to disable logging
  -v, --log-verbose                     Enable verbose logs
  -p, --password string                 Leave empty to use an auto generated
                                        value
  -g, --permissions strings             User's permissions. "*" means any
                                        permission (default [list,download])
  -k, --public-key strings
      --s3-access-key string
      --s3-access-secret string
      --s3-bucket string
      --s3-endpoint string
      --s3-key-prefix string            Allows to restrict access to the
                                        virtual folder identified by this
                                        prefix and its contents
      --s3-region string
      --s3-storage-class string
      --s3-upload-concurrency int       How many parts are uploaded in
                                        parallel (default 2)
      --s3-upload-part-size int         The buffer size for multipart uploads
                                        (MB) (default 5)
  -s, --sftpd-port int                  0 means a random unprivileged port,
                                        < 0 disabled
  -c, --ssh-commands strings            SSH commands to enable.
                                        "*" means any supported SSH command
                                        including scp
                                         (default [md5sum,sha1sum,cd,pwd,scp])
  -u, --username string                 Leave empty to use an auto generated
                                        value
      --webdav-cert string              Path to the certificate file for WebDAV
                                        over HTTPS
      --webdav-key string               Path to the key file for WebDAV over
                                        HTTPS
      --webdav-port int                 0 means a random unprivileged port,
                                        < 0 disabled (default -1)
```

In portable mode, SFTPGo can advertise the SFTP/FTP services and, optionally, the credentials via multicast DNS, so there is a standard way to discover the service and to automatically connect to it.

Here is an example of the advertised SFTP service including credentials as seen using `avahi-browse`:

```console
= enp0s31f6 IPv4 SFTPGo portable 53705                         SFTP File Transfer   local
   hostname = [p1.local]
   address = [192.168.1.230]
   port = [53705]
   txt = ["password=EWOo6pJe" "user=user" "version=0.9.3-dev-b409523-dirty-2019-10-26T13:43:32Z"]
```
