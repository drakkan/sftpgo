# Key Management Services

SFTPGo stores sensitive data such as Cloud account credentials or passphrases to derive per-object encryption keys. These data are stored as ciphertext and only loaded to RAM in plaintext when needed.

## Supported Services for encryption and decryption

The `secrets` section of the `kms` configuration allows to configure how to encrypt and decrypt sensitive data. The following configuration parameters are available:

- `url` defines the URI to the KMS service
- `master_key`, defines the master encryption key as string. If not empty, it takes precedence over `master_key_path`.
- `master_key_path` defines the absolute path to a file containing the master encryption key. This could be, for example, a docker secret or a file protected with filesystem level permissions.

### Local provider

If the `url` is empty SFTPGo uses local encryption for keeping secrets. Internally, it uses the [NaCl secret box](https://pkg.go.dev/golang.org/x/crypto/nacl/secretbox) algorithm to perform encryption and authentication.

We first generate a random key, then the per-object encryption key is derived from this random key in the following way:

1. a master key is provided: the encryption key is derived using the HMAC-based Extract-and-Expand Key Derivation Function (HKDF) as defined in [RFC 5869](http://tools.ietf.org/html/rfc5869)
2. no master key is provided: the encryption key is derived as simple hash of the random key. This is the default configuration.

For compatibility with SFTPGo versions 1.2.x and before we also support encryption based on `AES-256-GCM`. The data encrypted with this algorithm will never use the master key to keep backward compatibility. You can activate it using `builtin://` as `url` but this is not recommended.

### Cloud providers

Several cloud providers are supported using the [sftpgo-plugin-kms](https://github.com/sftpgo/sftpgo-plugin-kms).

### Notes

- The KMS configuration is global.
- If you set a master key you will be unable to decrypt the data without this key and the SFTPGo users that need the data as plain text will be unable to login.
- You can start using the local provider and then switch to an external one but you can't switch between external providers and still be able to decrypt the data encrypted using the previous provider.
