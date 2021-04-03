# SFTP as storage backend

An SFTP account on another server can be used as storage for an SFTPGo account, so the remote SFTP server can be accessed in a similar way to the local file system.

Here are the supported configuration parameters:

- `Endpoint`, ssh endpoint as `host:port`
- `Username`
- `Password`
- `PrivateKey`
- `Fingerprints`
- `Prefix`
- `BufferSize`

The mandatory parameters are the endpoint, the username and a password or a private key. If you define both a password and a private key the key is tried first. The provided private key should be PEM encoded, something like this:

```shell
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACA8LWc4SahqKkAr4L3rS19w1Vt8/IAf4th2FZmf+PJ/vwAAAJBvnZIJb52S
CQAAAAtzc2gtZWQyNTUxOQAAACA8LWc4SahqKkAr4L3rS19w1Vt8/IAf4th2FZmf+PJ/vw
AAAEBE6F5Az4wzNfNYLRdG8blDwvPBYFXE8BYDi4gzIhnd9zwtZzhJqGoqQCvgvetLX3DV
W3z8gB/i2HYVmZ/48n+/AAAACW5pY29sYUBwMQECAwQ=
-----END OPENSSH PRIVATE KEY-----
```

The password and the private key are stored as ciphertext according to your [KMS configuration](./kms.md).

SHA256 fingerprints for remote server host keys are optional but highly recommended: if you provide one or more fingerprints the server host key will be verified against them and the connection will be denied if none of the fingerprints provided match that for the server host key.

Specifying a prefix you can restrict all operations to a given path within the remote SFTP server.

Buffering can be enabled by setting a buffer size (in MB) greater than 0. By enabling buffering, the reads and writes, from/to the remote SFTP server, are split in multiple concurrent requests and this allows data to be transferred at a faster rate, over high latency networks, by overlapping round-trip times. With buffering enabled, resuming uploads and trucate are not supported and a file cannot be opened for both reading and writing at the same time. 0 means disabled.

Some SFTP servers (eg. AWS Transfer) do not support opening files read/write at the same time, you can enable buffering to work with them.
