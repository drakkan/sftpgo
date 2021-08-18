# Data At Rest Encryption (DARE)

SFTPGo supports data at-rest encryption via its `cryptfs` virtual file system, in this mode SFTPGo transparently encrypts and decrypts data (to/from the local disk) on-the-fly during uploads and/or downloads, making sure that the files at-rest on the server-side are always encrypted.

Data At Rest Encryption is supported for local filesystem, for cloud storage backends you can use their server side encryption feature.

So, because of the way it works, as described here above, when you set up an encrypted filesystem for a user you need to make sure it points to an empty path/directory (that has no files in it). Otherwise, it would try to decrypt existing files that are not encrypted in the first place and fail.

The SFTPGo's `cryptfs` is a tiny wrapper around [sio](https://github.com/minio/sio) therefore data is encrypted and authenticated using `AES-256-GCM` or `ChaCha20-Poly1305`. AES-GCM will be used if the CPU provides hardware support for it.

The only required configuration parameter is a `passphrase`, each file will be encrypted using an unique, randomly generated secret key derived from the given passphrase using the HMAC-based Extract-and-Expand Key Derivation Function (HKDF) as defined in [RFC 5869](http://tools.ietf.org/html/rfc5869). It is important to note that the per-object encryption key is never stored anywhere: it is derived from your `passphrase` and a randomly generated initialization vector just before encryption/decryption. The initialization vector is stored with the file.

The passphrase is stored encrypted itself according to your [KMS configuration](./kms.md) and is required to decrypt any file encrypted using an encryption key derived from it.

The encrypted filesystem has some limitations compared to the local, unencrypted, one:

- Resuming uploads is not supported.
- Opening a file for both reading and writing at the same time is not supported and so clients that require advanced filesystem-like features such as `sshfs` are not supported too.
- Truncate is not supported.
- System commands such as `git` or `rsync` are not supported: they will store data unencrypted.
