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
      --az-download-concurrency int     How many parts are downloaded in
                                        parallel (default 5)
      --az-download-part-size int       The buffer size for multipart downloads
                                        (MB) (default 5)
      --az-endpoint string              Leave empty to use the default:
                                        "blob.core.windows.net"
      --az-key-prefix string            Allows to restrict access to the
                                        virtual folder identified by this
                                        prefix and its contents
      --az-sas-url string               Shared access signature URL
      --az-upload-concurrency int       How many parts are uploaded in
                                        parallel (default 5)
      --az-upload-part-size int         The buffer size for multipart uploads
                                        (MB) (default 5)
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
  -f, --fs-provider string              osfs => local filesystem (legacy value: 0)
                                        s3fs => AWS S3 compatible (legacy: 1)
                                        gcsfs => Google Cloud Storage (legacy: 2)
                                        azblobfs => Azure Blob Storage (legacy: 3)
                                        cryptfs => Encrypted local filesystem (legacy: 4)
                                        sftpfs => SFTP (legacy: 5) (default "osfs")
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
      --log-utc-time                    Use UTC time for logging
  -v, --log-verbose                     Enable verbose logs
  -p, --password string                 Leave empty to use an auto generated
                                        value
  -g, --permissions strings             User's permissions. "*" means any
                                        permission (default [list,download])
  -k, --public-key strings
      --s3-access-key string
      --s3-access-secret string
      --s3-acl string
      --s3-bucket string
      --s3-endpoint string
      --s3-force-path-style             Force path style bucket URL
      --s3-key-prefix string            Allows to restrict access to the
                                        virtual folder identified by this
                                        prefix and its contents
      --s3-region string
      --s3-role-arn string
      --s3-storage-class string
      --s3-upload-concurrency int       How many parts are uploaded in
                                        parallel (default 2)
      --s3-upload-part-size int         The buffer size for multipart uploads
                                        (MB) (default 5)
      --sftp-buffer-size int            The size of the buffer (in MB) to use
                                        for transfers. By enabling buffering,
                                        the reads and writes, from/to the
                                        remote SFTP server, are split in
                                        multiple concurrent requests and this
                                        allows data to be transferred at a
                                        faster rate, over high latency networks,
                                        by overlapping round-trip times
      --sftp-disable-concurrent-reads   Concurrent reads are safe to use and
                                        disabling them will degrade performance.
                                        Disable for read once servers
      --sftp-endpoint string            SFTP endpoint as host:port for SFTP
                                        provider
      --sftp-fingerprints strings       SFTP fingerprints to verify remote host
                                        key for SFTP provider
      --sftp-key-path string            SFTP private key path for SFTP provider
      --sftp-password string            SFTP password for SFTP provider
      --sftp-prefix string              SFTP prefix allows restrict all
                                        operations to a given path within the
                                        remote SFTP server
      --sftp-username string            SFTP user for SFTP provider
  -s, --sftpd-port int                  0 means a random unprivileged port,
                                        < 0 disabled
  -c, --ssh-commands strings            SSH commands to enable.
                                        "*" means any supported SSH command
                                        including scp
                                         (default [md5sum,sha1sum,sha256sum,cd,pwd,scp])
      --start-directory string          Alternate start directory.
                                        This is a virtual path not a filesystem
                                        path (default "/")
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
