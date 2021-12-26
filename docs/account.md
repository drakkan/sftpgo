# Account's configuration properties

Please take a look at the [OpenAPI schema](../openapi/openapi.yaml) for the exact definitions of user, folder and admin fields.
If you need an example you can export a dump using the Web Admin or by invoking the `dumpdata` endpoint directly, you need to obtain an access token first, for example:

```shell
$ curl "http://admin:password@127.0.0.1:8080/api/v2/token"
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiQVBJIl0sImV4cCI6MTYxMzMzNTI2MSwianRpIjoiYzBrb2gxZmNkcnBjaHNzMGZwZmciLCJuYmYiOjE2MTMzMzQ2MzEsInBlcm1pc3Npb25zIjpbIioiXSwic3ViIjoiYUJ0SHUwMHNBUmxzZ29yeEtLQ1pZZWVqSTRKVTlXbThHSGNiVWtWVmc1TT0iLCJ1c2VybmFtZSI6ImFkbWluIn0.WiyqvUF-92zCr--y4Q_sxn-tPnISFzGZd_exsG-K7ME","expires_at":"2021-02-14T20:41:01Z"}

curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiQVBJIl0sImV4cCI6MTYxMzMzNTI2MSwianRpIjoiYzBrb2gxZmNkcnBjaHNzMGZwZmciLCJuYmYiOjE2MTMzMzQ2MzEsInBlcm1pc3Npb25zIjpbIioiXSwic3ViIjoiYUJ0SHUwMHNBUmxzZ29yeEtLQ1pZZWVqSTRKVTlXbThHSGNiVWtWVmc1TT0iLCJ1c2VybmFtZSI6ImFkbWluIn0.WiyqvUF-92zCr--y4Q_sxn-tPnISFzGZd_exsG-K7ME" "http://127.0.0.1:8080/api/v2/dumpdata?output-data=1"
```

the dump is a JSON with all SFTPGo data including users, folders, admins.

These properties are stored inside the configured data provider.

SFTPGo supports checking passwords stored with bcrypt, pbkdf2, md5crypt and sha512crypt too. For pbkdf2 the supported format is `$<algo>$<iterations>$<salt>$<hashed pwd base64 encoded>`, where algo is `pbkdf2-sha1` or `pbkdf2-sha256` or `pbkdf2-sha512` or `$pbkdf2-b64salt-sha256$`. For example the pbkdf2-sha256 of the word password using 150000 iterations and E86a9YMX3zC7 as salt must be stored as `$pbkdf2-sha256$150000$E86a9YMX3zC7$R5J62hsSq+pYw00hLLPKBbcGXmq7fj5+/M0IFoYtZbo=`. In pbkdf2 variant with b64salt the salt is base64 encoded. For bcrypt the format must be the one supported by golang's crypto/bcrypt package, for example the password secret with cost 14 must be stored as `$2a$14$ajq8Q7fbtFRQvXpdCq7Jcuy.Rx1h/L4J60Otx.gyNLbAYctGMJ9tK`. For md5crypt and sha512crypt we support the format used in `/etc/shadow` with the `$1$` and `$6$` prefix, this is useful if you are migrating from Unix system user accounts. We support Apache md5crypt (`$apr1$` prefix) too. Using the REST API you can send a password hashed as bcrypt, pbkdf2, md5crypt or sha512crypt and it will be stored as is.

If you want to use your existing accounts, you have these options:

- you can import your users inside SFTPGo. Take a look at [convert users](.../examples/convertusers) script, it can convert and import users from Linux system users and Pure-FTPd/ProFTPD virtual users
- you can use an external authentication program
