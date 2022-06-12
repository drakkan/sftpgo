# HTTP/S storage backend

SFTPGo can use custom storage backend implementations compliant with the REST API documented [here](./../openapi/httpfs.yaml).

:warning: HTTPFs is a work in progress and makes no API stability promises.

The only required parameter is the HTTP/S endpoint that SFTPGo must use to make API calls.
If you define `http://127.0.0.1:9999/api/v1` as endpoint, SFTPGo will add the API path, for example for the `stat` API it will invoke `http://127.0.0.1:9999/api/v1/stat/{name}`.

You can set a `username` and/or a `password` to instruct SFTPGo to use the basic authentication, or you can set an API key to instruct SFTPGo to add it to each API call in the `X-API-KEY` HTTP header.

Here is a mapping between HTTP response codes and protocol errors:

- `401`, `403` mean permission denied error
- `404`, means not found error
- `501`, means not supported error
- `200`, `201`, mean no error
- any other response code means a generic error
