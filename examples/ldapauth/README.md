# LDAPAuth

This is an example for an external authentication program. It performs authentication against an LDAP server.
It is tested against [389ds](https://directory.fedoraproject.org/) and can be used as starting point to authenticate using any LDAP server including Active Directory.

You need to change the LDAP connection parameters and the user search query to match your environment.
You can build this example using the following command:

```console
go build -ldflags "-s -w" -o ldapauth
```

This program assumes that the 389ds schema was extended to add support for public keys using the following ldif file placed in `/etc/dirsrv/schema/98openssh-ldap.ldif`:

```console
dn: cn=schema
changetype: modify
add: attributetypes
attributetypes: ( 1.3.6.1.4.1.24552.500.1.1.1.13 NAME 'sshPublicKey' DESC 'MANDATORY: OpenSSH Public key' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
-
add: objectclasses
objectClasses: ( 1.3.6.1.4.1.24552.500.1.1.2.0 NAME 'ldapPublicKey' SUP top AUXILIARY DESC 'MANDATORY: OpenSSH LPK objectclass' MUST ( uid ) MAY ( sshPublicKey ) )
-

dn: cn=sshpublickey,cn=default indexes,cn=config,cn=ldbm database,cn=plugins,cn=config
changetype: add
cn: sshpublickey
nsIndexType: eq
nsIndexType: pres
nsSystemIndex: false
objectClass: top
objectClass: nsIndex

dn: cn=sshpublickey_self_manage,ou=groups,dc=example,dc=com
changetype: add
objectClass: top
objectClass: groupofuniquenames
cn: sshpublickey_self_manage
description: Members of this group gain the ability to edit their own sshPublicKey field

dn: dc=example,dc=com
changetype: modify
add: aci
aci: (targetattr = "sshPublicKey") (version 3.0; acl "Allow members of sshpublickey_self_manage to edit their keys"; allow(write) (groupdn = "ldap:///cn=sshpublickey_self_manage,ou=groups,dc=example,dc=com" and userdn="ldap:///self" ); )
-
```

Please feel free to send pull requests to improve this example authentication program, thanks!
