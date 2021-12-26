# Azure Blob Storage backend

To connect SFTPGo to Azure Blob Storage, you need to specify the access credentials. Azure Blob Storage has different options for credentials, we support:

1. Providing an account name and account key.
2. Providing a shared access signature (SAS).

If you authenticate using account and key you also need to specify a container. The endpoint can generally be left blank, the default is `blob.core.windows.net`.

If you provide a SAS URL the container is optional and if given it must match the one inside the shared access signature.

If you want to connect to an emulator such as [Azurite](https://github.com/Azure/Azurite) you need to provide the account name/key pair and an endpoint prefixed with the protocol, for example `http://127.0.0.1:10000`.

Specifying a different `key_prefix`, you can assign different "folders" of the same container to different users. This is similar to a chroot directory for local filesystem. Each SFTPGo user can only access the assigned folder and its contents. The folder identified by `key_prefix` does not need to be pre-created.

For multipart uploads you can customize the parts size and the upload concurrency. Please note that if the upload bandwidth between the client and SFTPGo is greater than the upload bandwidth between SFTPGo and the Azure Blob service then the client should wait for the last parts to be uploaded to Azure after finishing uploading the file to SFTPGo, and it may time out. Keep this in mind if you customize these parameters.

The configured container must exist.

This backend is very similar to the [S3](./s3.md) backend, and it has the same limitations. As with S3 `chtime` will fail with the default configuration, you can install the [metadata plugin](https://github.com/sftpgo/sftpgo-plugin-metadata) to make it work and thus be able to preserve/change file modification times.
