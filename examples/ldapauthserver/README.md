# LDAPAuthServer

This is an example for an HTTP server to use as external authentication HTTP hook. It performs authentication against an LDAP server.
It is tested against [389ds](https://directory.fedoraproject.org/) and can be used as starting point to authenticate using any LDAP server including Active Directory.

You can configure the server using the [ldapauth.toml](./ldapauth.toml) configuration file.
You can build this example using the following command:

```console
go build -ldflags "-s -w" -o ldapauthserver
```
