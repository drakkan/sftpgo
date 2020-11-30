# Authy

These example show how-to integrate [Twilio Authy API](https://www.twilio.com/docs/authy/api) for One-Time-Password logins.

The examples assume that the user has the free [Authy app](https://authy.com/) installed and uses it to generate offline [TOTP](https://en.wikipedia.org/wiki/Time-based_One-time_Password_algorithm) codes (soft tokens).

You first need to [create an Authy Application in the Twilio Console](https://twilio.com/console/authy/applications?_ga=2.205553366.451688189.1597667213-1526360003.1597667213), then you can create a new Authy user and store a reference to the matching SFTPGo account.

Verify that your Authy application is successfully registered:

```bash
export AUTHY_API_KEY=<your api key here>
curl 'https://api.authy.com/protected/json/app/details' -H "X-Authy-API-Key: $AUTHY_API_KEY"
```

now create an Authy user:

```bash
curl -XPOST "https://api.authy.com/protected/json/users/new" \
-H "X-Authy-API-Key: $AUTHY_API_KEY" \
--data-urlencode user[email]="user@domain.com" \
--data-urlencode user[cellphone]="317-338-9302" \
--data-urlencode user[country_code]="54"
```

The response is something like this:

```json
{"message":"User created successfully.","user":{"id":xxxxxxxx},"success":true}
```

Save the user id somewhere and add a reference to the matching SFTPGo account. You could also store this ID in the `additional_info` SFTPGo user field.

After this step you can use the Authy app installed on your phone to generate TOTP codes.

Now you can verify the token using an HTTP GET request:

```bash
export TOKEN=<TOTP you read from Authy app>
export AUTHY_ID=<user id>
curl -i "https://api.authy.com/protected/json/verify/${TOKEN}/${AUTHY_ID}" \
    -H "X-Authy-API-Key: $AUTHY_API_KEY"
```

So inside your hook you need to check:

- the HTTP response code for the verify request, it must be `200`
- the JSON reponse body, it must contains the key `success` with the value `true` (as string)

If these conditions are met the token is valid and you allow the user to login.

We provide the following examples:

- [Keyboard interactive authentication](./keyint/README.md) for 2FA using password + Authy one time token.
- [External authentication](./extauth/README.md) using Authy one time tokens as passwords.
- [Check password hook](./checkpwd/README.md) for 2FA using a password consisting of a fixed string and a One Time Token.

Please note that these are sample programs not intended for production use, you should write your own hook based on them and you should prefer HTTP based hooks if performance is a concern.
