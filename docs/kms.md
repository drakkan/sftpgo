# Key Management Services

SFTPGo stores sensitive data such as Cloud accounts credentials or passphrases to derive per-object encryption keys. These data are stored as ciphertext and only loaded to RAM in plaintext when needed.

## Supported Services for encryption and decryption

The `secrets` section of the `kms` configuration allows to configure how to encrypt and decrypt sensitive data. The following configuration parameters are available:

- `url` defines the URI to the KMS service
- `master_key_path` defines the absolute path to a file containing the master encryption key. This could be, for example, a docker secrets or a file protected with filesystem level permissions.

We use [Go CDK](https://gocloud.dev/howto/secrets/) to access several key management services in a portable way.

### Local provider

If the `url` is empty SFTPGo uses local encryption for keeping secrets. Internally, it uses the [NaCl secret box](https://godoc.org/golang.org/x/crypto/nacl/secretbox) algorithm to perform encryption and authentication.

We first generate a random key, then the per-object encryption key is derived from this random key in the following way:

1. a master key is provided: the encryption key is derived using the HMAC-based Extract-and-Expand Key Derivation Function (HKDF) as defined in [RFC 5869](http://tools.ietf.org/html/rfc5869)
2. no master key is provided: the encryption key is derived as simple hash of the random key. This is the default configuration.

For compatibility with SFTPGo versions 1.2.x and before we also support encryption based on `AES-256-GCM`. The data encrypted with this algorithm will never use the master key to keep backward compatibility.

### Google Cloud Key Management Service

To use keys from Google Cloud Platform’s [Key Management Service](https://cloud.google.com/kms/) (GCP KMS) you have to use `gcpkms` as URL scheme like this:

```shell
gcpkms://projects/[PROJECT_ID]/locations/[LOCATION]/keyRings/[KEY_RING]/cryptoKeys/[KEY]
```

SFTPGo will use Application Default Credentials. See [here](https://cloud.google.com/docs/authentication/production) for alternatives such as environment variables.

The URL host+path are used as the key resource ID; see [here](https://cloud.google.com/kms/docs/object-hierarchy#key) for more details.

If a master key is provided we first encrypt the plaintext data using the local provider and then we encrypt the resulting payload using the Cloud provider and store this ciphertext.

### AWS Key Management Service

To use customer master keys from Amazon Web Service’s [Key Management Service](https://aws.amazon.com/kms/) (AWS KMS) you have to use `awskms` as URL scheme. You can use the key’s ID, alias, or Amazon Resource Name (ARN) to identify the key. You should specify the region query parameter to ensure your application connects to the correct region.

Here are some examples:

- By ID: `awskms://1234abcd-12ab-34cd-56ef-1234567890ab?region=us-east-1`
- By alias: `awskms://alias/ExampleAlias?region=us-east-1`
- By ARN: `arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34bc-56ef-1234567890ab?region=us-east-1`

SFTPGo will use the default AWS session. See [AWS Session](https://docs.aws.amazon.com/sdk-for-go/api/aws/session/) to learn about authentication alternatives such as environment variables.

If a master key is provided we first encrypt the plaintext data using the local provider and then we encrypt the resulting payload using the Cloud provider and store this ciphertext.

### HashiCorp Vault

To use the [transit secrets engine](https://www.vaultproject.io/docs/secrets/transit/index.html) in [Vault](https://www.vaultproject.io/) you have to use `hashivault` as URL scheme like this: `hashivault://mykey`.

The Vault server endpoint and authentication token are specified using the environment variables `VAULT_SERVER_URL` and `VAULT_SERVER_TOKEN`, respectively.

If a master key is provided we first encrypt the plaintext data using the local provider and then we encrypt the resulting payload using Vault and store this ciphertext.

### Notes

- The KMS configuration is global.
- If you set a master key you will be unable to decrypt the data without this key and the SFTPGo users that need the data as plain text will be unable to login.
- You can start using the local provider and then switch to an external one but you can't switch between external providers and still be able to decrypt the data encrypted using the previous provider.
