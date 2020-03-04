# Google Cloud Storage backend

To connect SFTPGo to Google Cloud Storage, you can use use the Application Default Credentials (ADC) strategy to try to find your application's credentials automatically or you can explicitly provide a JSON credentials file that you can obtain from the Google Cloud Console. Take a look [here](https://cloud.google.com/docs/authentication/production#providing_credentials_to_your_application) for details.

You can optionally specify a [storage class](https://cloud.google.com/storage/docs/storage-classes) too. Leave it blank to use the default storage class.

