# WebDAV

The experimental `WebDAV` support can be enabled setting a `bind_port` inside the `webdavd` configuration section.

Each user has his own path like `http/s://<SFTPGo ip>:<WevDAVPORT>/<username>` and it must authenticate using password credentials.

WebDAV should work as expected for most use cases but there are some minor issues and some missing features.

Know issues:

- removing a directory tree on Cloud Storage backends could generate a `not found` error when removing the last (virtual) directory. This happen if the client cycles the directories tree itself and removes files and directories one by one instead of issuing a single remove command
- the used [WebDAV library](https://pkg.go.dev/golang.org/x/net/webdav?tab=doc) asks to open a file to execute a `stat` and sometime reads some bytes to find the content type. We are unable to distinguish a `stat` from a `download` for now, so to be able to proper list a directory you need to grant both `list` and `download` permissions
- the used `WebDAV library` not always returns a proper error code/message, most of the times it simply returns `Method not Allowed`. I'll try to improve the library error codes in the future
- WebDAV is quite a different protocol than SCP/FTP, there is no session concept, each command is a separate HTTP request, we could improve the performance by caching, for a small time, the user info so we don't need a user lookup (and so a dataprovider query) for each request. Some clients issue a lot of requests only for listing a directory contents. This needs more investigation and a design decision anyway the protocol itself is quite heavy
- if an object within a directory cannot be accessed, for example due to OS permissions issues or because is a missing mapped path for a virtual folder, the directory listing will fail. In SFTP/FTP the directory listing will succeed and you'll only get an error if you try to access to the problematic file/directory

We plan to add the following features in future releases:

- [CORS](http://www.w3.org/TR/cors/) support
- [Dead Properties](https://tools.ietf.org/html/rfc4918#section-3) support. We need a design decision here, probably the best solution is to store dead properties inside the data provider but this could increase a lot its size. Alternately we could store them on disk for local filesystem and add as metadata for Cloud Storage, this means that we need to do a separate `HEAD` request to retrieve dead properties for an S3 file. For big folders will do a lot of requests to the Cloud Provider, I don't like this solution. Another option is to expose a hook and allow you to implement `dead properties` outside SFTPGo.

If you find any other quircks or problems please let us know opening a GitHub issue, thank you!
