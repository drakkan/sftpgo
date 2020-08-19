# Authy 2FA via check password hook

This example shows how to use 2FA via the check password hook using a password consisting of a fixed part and an Authy TOTP token. The hook will check the TOTP token using the Authy API and SFTPGo will check the fixed part. Please read the [sample code](./main.go), it should be self explanatory.
