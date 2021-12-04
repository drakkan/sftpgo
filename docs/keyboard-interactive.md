# Keyboard Interactive Authentication

Keyboard interactive authentication is, in general, a series of questions asked by the server with responses provided by the client.
This authentication method is typically used for multi-factor authentication.
There are no restrictions on the number of questions asked on a particular authentication stage; there are also no restrictions on the number of stages involving different sets of questions.

To enable keyboard interactive authentication, you must set the absolute path of your authentication program or an HTTP URL using the  `keyboard_interactive_auth_hook` key in your configuration file.

The external program can read the following environment variables to get info about the user trying to authenticate:

- `SFTPGO_AUTHD_USERNAME`
- `SFTPGO_AUTHD_IP`
- `SFTPGO_AUTHD_PASSWORD`, this is the hashed password as stored inside the data provider

Previous global environment variables aren't cleared when the script is called. The content of these variables is _not_ quoted. They may contain special characters.

The program must write the questions on its standard output, in a single line, using the following struct JSON serialized:

- `instruction`, string. A short description to show to the user that is trying to authenticate. Can be empty or omitted
- `questions`, list of questions to be asked to the user
- `echos` list of boolean flags corresponding to the questions (so the lengths of both lists must be the same) and indicating whether user's reply for a particular question should be echoed on the screen while they are typing: true if it should be echoed, or false if it should be hidden.
- `check_password` optional integer. Ask exactly one question and set this field to `1` if the expected answer is the user password and you want that SFTPGo checks it for you or to `2` if the user has the SFTPGo built-in TOTP enabled and the expected answer is the user one time passcode. If the password/passcode is correct, the returned response to the program is `OK`. If the password is wrong, the program will be terminated and an authentication error will be returned to the user that is trying to authenticate.
- `auth_result`, integer. Set this field to 1 to indicate successful authentication. 0 is ignored. Any other value means authentication error. If this field is found and it is different from 0 then SFTPGo will not read any other questions from the external program, and it will finalize the authentication.

SFTPGo writes the user answers to the program standard input, one per line, in the same order as the questions.
Please be sure that your program receives the answers for all the issued questions before asking for the next ones.

Keyboard interactive authentication can be chained to the external authentication.
The authentication must finish within 60 seconds.

Let's see a very basic example. Our sample keyboard interactive authentication program will ask for 2 sets of questions and accept the user if the answer to the last question is `answer3`.

```shell
#!/bin/sh

echo '{"questions":["Question1: ","Question2: "],"instruction":"This is a sample for keyboard interactive authentication","echos":[true,false]}'

read ANSWER1
read ANSWER2

echo '{"questions":["Question3: "],"instruction":"","echos":[true]}'

read ANSWER3

if test "$ANSWER3" = "answer3"; then
  echo '{"auth_result":1}'
else
  echo '{"auth_result":-1}'
fi
```

and here is an example where SFTPGo checks the user password for you:

```shell
#!/bin/sh

echo '{"questions":["Password: "],"instruction":"This is a sample for keyboard interactive authentication","echos":[false],"check_password":1}'

read ANSWER1

if test "$ANSWER1" != "OK"; then
  exit 1
fi

echo '{"questions":["One time token: "],"instruction":"","echos":[false]}'

read ANSWER2

if test "$ANSWER2" = "token"; then
  echo '{"auth_result":1}'
else
  echo '{"auth_result":-1}'
fi
```

If the hook is an HTTP URL then it will be invoked as HTTP POST multiple times for each login request.
The request body will contain a JSON struct with the following fields:

- `request_id`, string. Unique request identifier
- `step`, integer. Counter starting from 1
- `username`, string
- `ip`, string
- `password`, string. This is the hashed password as stored inside the data provider
- `answers`, list of string. It will be null for the first request
- `questions`, list of string. It will contain the previously asked questions. It will be null for the first request

The HTTP response code must be 200 and the body must contain the same JSON struct described for the program.

Let's see a basic sample, the configured hook is `http://127.0.0.1:8000/keyIntHookPwd`, as soon as the user tries to login, SFTPGo makes this HTTP POST request:

```shell
POST /keyIntHookPwd HTTP/1.1
Host: 127.0.0.1:8000
User-Agent: Go-http-client/1.1
Content-Length: 189
Content-Type: application/json
Accept-Encoding: gzip

{"request_id":"bq1r5r7cdrpd2qtn25ng","username":"a","ip":"127.0.0.1","step":1,"password":"$pbkdf2-sha512$150000$ClOPkLNujMTL$XktKy0xuJsOfMYBz+f2bIyPTdbvDTSnJ1q+7+zp/HPq5Qojwp6kcpSIiVHiwvbi8P6HFXI/D3UJv9BLcnQFqPA=="}
```

as you can see in this first requests `answers` and `questions` are null.

Here is the response that instructs SFTPGo to ask for the user password and to check it:

```shell
HTTP/1.1 200 OK
Date: Tue, 31 Mar 2020 21:15:24 GMT
Server: WSGIServer/0.2 CPython/3.8.2
Content-Type: application/json
X-Frame-Options: SAMEORIGIN
Content-Length: 143

{"questions": ["Password: "], "check_password": 1, "instruction": "This is a sample for keyboard interactive authentication", "echos": [false]}
```

The user enters the correct password and so SFTPGo makes a new HTTP POST, please note that the `request_id` is the same of the previous request, this time the asked `questions` and the user's `answers` are not null:

```shell
POST /keyIntHookPwd HTTP/1.1
Host: 127.0.0.1:8000
User-Agent: Go-http-client/1.1
Content-Length: 233
Content-Type: application/json
Accept-Encoding: gzip

{"request_id":"bq1r5r7cdrpd2qtn25ng","step":2,"username":"a","ip":"127.0.0.1","password":"$pbkdf2-sha512$150000$ClOPkLNujMTL$XktKy0xuJsOfMYBz+f2bIyPTdbvDTSnJ1q+7+zp/HPq5Qojwp6kcpSIiVHiwvbi8P6HFXI/D3UJv9BLcnQFqPA==","answers":["OK"],"questions":["Password: "]}
```

Here is the HTTP response that instructs SFTPGo to ask for a new question:

```shell
HTTP/1.1 200 OK
Date: Tue, 31 Mar 2020 21:15:27 GMT
Server: WSGIServer/0.2 CPython/3.8.2
Content-Type: application/json
X-Frame-Options: SAMEORIGIN
Content-Length: 66

{"questions": ["Question2: "], "instruction": "", "echos": [true]}
```

As soon as the user answer to this question, SFTPGo will make a new HTTP POST request with the user's answers:

```shell
POST /keyIntHookPwd HTTP/1.1
Host: 127.0.0.1:8000
User-Agent: Go-http-client/1.1
Content-Length: 239
Content-Type: application/json
Accept-Encoding: gzip

{"request_id":"bq1r5r7cdrpd2qtn25ng","step":3,"username":"a","ip":"127.0.0.1","password":"$pbkdf2-sha512$150000$ClOPkLNujMTL$XktKy0xuJsOfMYBz+f2bIyPTdbvDTSnJ1q+7+zp/HPq5Qojwp6kcpSIiVHiwvbi8P6HFXI/D3UJv9BLcnQFqPA==","answers":["answer2"],"questions":["Question2: "]}
```

Here is the final HTTP response that allows the user login:

```shell
HTTP/1.1 200 OK
Date: Tue, 31 Mar 2020 21:15:29 GMT
Server: WSGIServer/0.2 CPython/3.8.2
Content-Type: application/json
X-Frame-Options: SAMEORIGIN
Content-Length: 18

{"auth_result": 1}
```

An example keyboard interactive program allowing to authenticate using [Twilio Authy 2FA](https://www.twilio.com/docs/authy) can be found inside the source tree [authy](../examples/OTP/authy) directory.
