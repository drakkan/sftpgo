# WebDAV

The `WebDAV` support can be enabled by configuring one or more `bindings` inside the `webdavd` configuration section.

Each user can access their home directory using the path `http/s://<SFTPGo ip>:<WevDAVPORT>/<prefix>`. By default `prefix` is empty. If you define a prefix it must be an abosulte URI, for example `/dav`.

WebDAV is quite a different protocol than SFTP/FTP, there is no session concept, each command is a separate HTTP request and must be authenticated, to improve performance SFTPGo caches authenticated users. This way SFTPGo don't need to do a dataprovider query and a password check for each request.

The user caching configuration allows to set:

- `expiration_time` in minutes. If a user is cached for more than the specified minutes it will be removed from the cache and a new dataprovider query will be performed. Please note that the `last_login` field will not be updated and `external_auth_hook`, `pre_login_hook` and `check_password_hook` will not be executed if the user is obtained from the cache.
- `max_size`. Maximum number of users to cache. When this limit is reached the user with the oldest expiration date will be removed from the cache. 0 means no limit however the cache size cannot exceed the number of users so if you have a small number of users you can set this value to 0.

Users are automatically removed from the cache after an update/delete.

WebDAV protocol requires the MIME type for each file. SFTPGo will first try to guess the MIME type by extension. If this fails it will send a `HEAD` request for Cloud backends and, as last resort, it will try to guess the MIME type reading the first 512 bytes of the file. This may slow down the directory listing, especially for Cloud based backends, if you have directories containing many files with unregistered extensions. To mitigate this problem, you can enable caching of MIME types so that the MIME type detection is done only once.

The MIME types caching configurations allows to set the maximum number of MIME types to cache. Once the cache reaches the configured maximum size no new MIME types will be added. The MIME types cache  is a non-persistent in-memory cache. If you need a persistent cache add your MIME types to `/etc/mime.types` on Linux or inside the registry on Windows.

WebDAV should work as expected for most use cases but there are some minor issues and some missing features.

If you use WebDAV behind a reverse proxy ensure to preserve the `Host` header or `COPY`/`MOVE` operations will fail. For example for apache you have to set `ProxyPreserveHost On`.

Know issues:

- removing a directory tree on Cloud Storage backends could generate a `not found` error when removing the last (virtual) directory. This happens if the client cycles the directories tree itself and removes files and directories one by one instead of issuing a single remove command
- the used [WebDAV library](https://pkg.go.dev/golang.org/x/net/webdav?tab=doc) asks to open a file to execute a `stat` and sometimes reads some bytes to find the content type. Stat calls are executed before and after a download too, so to be able to properly list a directory you need to grant both `list` and `download` permissions and to be able to upload files you need to gran both `list` and `upload` permissions
- the used [WebDAV library](https://pkg.go.dev/golang.org/x/net/webdav?tab=doc) not always returns a proper error code/message, most of the times it simply returns `Method not Allowed`. I'll try to improve the library error codes in the future
- if a file or a directory cannot be accessed, for example due to OS permissions issues or because a mapped path for a virtual folder is a missing, it will be omitted from the directory listing. If there is a different error then the whole directory listing will fail. This behavior is different from SFTP/FTP where you will be able to see the problematic file/directory in the directory listing, you will only get an error if you try to access it
- if you use the native Windows client please check its usage and pay particular attention to the [registry settings](https://docs.microsoft.com/en-us/iis/publish/using-webdav/using-the-webdav-redirector#webdav-redirector-registry-settings). The default file size limit is 50MB and if you don't configure SFTPGo to use HTTPS you have to set `BasicAuthLevel` to `2`

We plan to add [Dead Properties](https://tools.ietf.org/html/rfc4918#section-3) support in future releases. We need a design decision here, probably the best solution is to store dead properties inside the data provider but this could increase a lot its size. Alternately we could store them on disk for local filesystem and add as metadata for Cloud Storage, this means that we need to do a separate `HEAD` request to retrieve dead properties for an S3 file. For big folders will do a lot of requests to the Cloud Provider, I don't like this solution. Another option is to expose a hook and allow you to implement `dead properties` outside SFTPGo.

If you find any other quirks or problems please let us know opening a GitHub issue, thank you!
