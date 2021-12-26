# Google Cloud Storage backend

To connect SFTPGo to Google Cloud Storage you can use use the Application Default Credentials (ADC) strategy to try to find your application's credentials automatically or you can explicitly provide a JSON credentials file that you can obtain from the Google Cloud Console. Take a look [here](https://cloud.google.com/docs/authentication/production#providing_credentials_to_your_application) for details.

Specifying a different `key_prefix`, you can assign different "folders" of the same bucket to different users. This is similar to a chroot directory for local filesystem. Each SFTP/SCP user can only access the assigned folder and its contents. The folder identified by `key_prefix` does not need to be pre-created.

You can optionally specify a [storage class](https://cloud.google.com/storage/docs/storage-classes) too. Leave it blank to use the default storage class.

The configured bucket must exist.

This backend is very similar to the [S3](./s3.md) backend, and it has the same limitations. As with S3 `chtime` will fail with the default configuration, you can install the [metadata plugin](https://github.com/sftpgo/sftpgo-plugin-metadata) to make it work and thus be able to preserve/change file modification times.
