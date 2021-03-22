# SFTPGo on Windows with Active Directory Integration + Caddy Static File Server Example

[![SFTPGo on Windows with Active Directory Integration + Caddy Static File Server Example](https://img.youtube.com/vi/M5UcJI8t4AI/0.jpg)](https://www.youtube.com/watch?v=M5UcJI8t4AI)

This is similar to the ldapauthserver example, but is more specific to using Active Directory along with using SFTPGo on a Windows Server.

The Youtube Walkthrough/Tutorial video above goes into considerable more detail, but in short, it walks through setting up SFTPGo on a new Windows Server, and enables the External Authentication feature within SFTPGo, along with my `sftpgo-ldap-http-server` project, to allow for user authentication into SFTPGo to occur through one or more Active Directory connections.

Additionally, I go through using the Caddy web server, to help enable serving of static files, if this is something that would be of interest for you.

To get started, you'll want to download the latest release ZIP package from the [sftpgo-ldap-http-server repository](https://github.com/orware/sftpgo-ldap-http-server).

The ZIP itself contains the `sftpgo-ldap-http-server.exe` file, along with an `OpenLDAP` folder (mainly to help if you want to use TLS for your LDAP connections), and a `Data` which contains a logs folder, a configuration.example.php file, a functions.php file, and the LICENSE and README files.

The video above goes through the whole process, but to get started you'll want to install SFTPGo on your server, and then extract the `sftpgo-ldap-http-server` ZIP file on the server as well into a separate folder. Then you'll want to copy the configuration.example.php file and name it `configuration.php` and begin customizing the settings (e.g. add in your own LDAP settings, along with how you may want to have your folders be created). At the very minimum you'll want to make sure that the home directories are set correctly to how you want the folders to be created for your environment (you don't have to use the virtual folders or really any of the other functionality if you don't need it).

Once configured, from a command prompt window, if you are already in the same folder as where you extracted the `sftpgo-ldap-http-server` ZIP, you may simply call the `sftpgo-ldap-http-server.exe` and it should start up a simple HTTP server on Port 9001 running on localhost (the port can be adjusted via the `configuration.php` file as well). Now all you have to do is point SFTPGo's `external_auth_hook` option to point to `http://localhost:9001/` and you should be able to run some authentication tests (assuming you have all of your settings correct and there are no intermediate issues).

The video above definitely goes through some troubleshooting situations you might find yourself coming across, so while it is long (at about 1 hour, 42 minutes), it may be helpful to review and avoid some issues and just to learn a bit more about SFTPGo and the integration above.

## Example Virtual Folders Configuration (Allowing for Both a Public and Private Folder)

The following can be utilized if you'd like to assign your users both a Private Virtual Folder and Public Virtual Folder.

By itself, the Public Virtual Folder isn't necessarily public, so keep that in mind. Only by combining things together with the Caddy web server (and Caddyfile example configuration down below) can you be successful in making the `F:\files\public` folder from the example public.

```php
$virtual_folders['example'] = [
    [
      //"id" => 0,
      "name" => "private-#USERNAME#",
      "mapped_path" => 'F:\files\private\#USERNAME#',
      //"used_quota_size" => 0,
      //"used_quota_files" => 0,
      //"last_quota_update" => 0,
      "virtual_path" => "/_private",
      "quota_size" => -1,
      "quota_files" => -1
    ],
	[
      //"id" => 0,
      "name" => "public-#USERNAME#",
      "mapped_path" => 'F:\files\public\#USERNAME#',
      //"used_quota_size" => 0,
      //"used_quota_files" => 0,
      //"last_quota_update" => 0,
      "virtual_path" => "/_public",
      "quota_size" => -1,
      "quota_files" => -1
    ]
];
```

## Example Connection "Output Object" Allowing For No Files in the User's Home Directory ("Root Directory") but Allowing for Files in the Public/Private Virtual Folders

The magic here happens in the "permissions" value, by limiting the root/home directory to just the list/download permissions, and then allowing all permissions on the Public/Private virtual folders.

```php
$connection_output_objects['example'] = [
    'status' => 1,
    'username' => '',
    'expiration_date' => 0,
    'home_dir' => '',
    'uid' => 0,
    'gid' => 0,
    'max_sessions' => 0,
    'quota_size' => 0,
    'quota_files' => 100000,
    'permissions' => [
        "/" => ["list", "download"],
        "/_private" => ["*"],
        "/_public" => ["*"],
    ],
    'upload_bandwidth' => 0,
    'download_bandwidth' => 0,
    'filters' => [
        'allowed_ip' => [],
        'denied_ip' => [],
    ],
    'public_keys' => [],
];
```

## Recommended Usage of Automatic Groups Mode (Limiting by Group Prefix)

The `sftpgo-ldap-http-server` project is able to automatically create virtual folders for any groups your user is a memberof if the automatic mode is turned on. However, by having a specific set of allowed prefixes defined, you can limit things to just those groups that begin with the prefixes you've listed, which can be helpful. The prefix itself will be removed from the group name when added as a virtual folder for the user.

```php
// If automatic groups mode is disabled, then you have to manually add the allowed groups into $allowed_groups down below:
// If enabled, then any groups you are a memberof will automatically be added in using the template below.
$auto_groups_mode = true;

$auto_groups_mode_virtual_folder_template = [
    [
      //"id" => 0,
      "name" => "groups-#GROUP#",
      "mapped_path" => 'F:\files\groups\#GROUP#',
      //"used_quota_size" => 0,
      //"used_quota_files" => 0,
      //"last_quota_update" => 0,
      "virtual_path" => "/groups/#GROUP#",
      "quota_size" => 0,
      "quota_files" => 100000
    ]
];

// Used only when auto groups mode is enabled and will help prevent all your groups from being
// added into SFTPGo since only groups with the prefixes defined here will be automatically added
// with prefixes automatically removed when listed as a virtual folder (e.g. a group with name
// "sftpgo-example" would simply become "example").
$allowed_group_prefixes = [
    'sftpgo-'
];
```

## Example Caddyfile Configuration You Can Adapt for Your Needs

```shell
### Re-usable snippets:

(add_static_file_serving_features) {

	# Allow accessing files without requiring .html:
	try_files {path} {path}.html

	# Enable Static File Server and Directory Browsing:
	file_server browse

	# Enable templating functionality:
	templates

	# Enable Compression for Output:
	encode zstd gzip

	handle_errors {
		respond "<pre>{http.error.status_code} {http.error.status_text}</pre>"
	}
}

(add_hsts_headers) {
	header {
		# Enable HTTP Strict Transport Security (HSTS) to force clients to always

		# connect via HTTPS (do not use if only testing)
		Strict-Transport-Security "max-age=31536000; includeSubDomains"

		# Enable cross-site filter (XSS) and tell browser to block detected attacks
		X-XSS-Protection "1; mode=block"

		# Prevent some browsers from MIME-sniffing a response away from the declared Content-Type
		X-Content-Type-Options "nosniff"

		# Disallow the site to be rendered within a frame (clickjacking protection)
		X-Frame-Options "DENY"

		# keep referrer data off of HTTP connections
		Referrer-Policy no-referrer-when-downgrade
	}
}

(add_logging_with_path) {
	log {
		output file "{args.0}" {
			roll_size 100mb
			roll_keep 5
			roll_keep_for 720h
		}

		format json
		#format console
		#format single_field common_log
	}
}

### Site Definitions:

public.example.com {

	# Site Root:
	root * F:\files\public

	import add_logging_with_path "F:\caddy\logs\public_example_com_access.log"
	import add_static_file_serving_features
	import add_hsts_headers
}


### Reverse Proxy Definitions:

webdav.example.com {
	reverse_proxy localhost:9000

	import add_logging_with_path "F:\caddy\logs\webdav_example_com_access.log"
}
```
