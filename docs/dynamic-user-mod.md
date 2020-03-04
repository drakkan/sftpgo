# Dynamic user modification

Dynamic user modification is supported via an external program that can be executed just before the user login.
To enable dynamic user modification, you must set the absolute path of your program using the `pre_login_program` key in your configuration file.

The external program can read the following environment variables to get info about the user trying to login:

- `SFTPGO_LOGIND_USER`, it contains the user trying to login serialized as JSON
- `SFTPGO_LOGIND_METHOD`, possible values are: `password`, `publickey` and `keyboard-interactive`

The program must write, on its the standard output, an empty string (or no response at all) if no user update is needed or the updated SFTPGo user serialized as JSON. Actions defined for users update will not be executed in this case.
The JSON response can include only the fields that need to the updated instead of the full user. For example, if you want to disable the user, you can return a response like this:

```json
{"status": 0}
```

The external program must finish within 60 seconds.

If an error happens while executing your program then login will be denied. "Dynamic user modification" and "External Authentication" are mutally exclusive.

Let's see a very basic example. Our sample program will grant access to the user `test_user` only in the time range 10:00-18:00. Other users will not be modified since the program will terminate with no output.

```
#!/bin/bash

CURRENT_TIME=`date +%H:%M`
if [[ "$SFTPGO_LOGIND_USER" =~ "\"test_user\"" ]]
then
  if [[ $CURRENT_TIME > "18:00" || $CURRENT_TIME < "10:00" ]]
  then
    echo '{"status":0}'
  else
    echo '{"status":1}'
  fi
fi
```

Please note that this is a demo program and it might not work in all cases. For example, the username should be obtained by parsing the JSON serialized user and not by searching the username inside the JSON as shown here.

