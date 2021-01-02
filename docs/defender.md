# Defender

The experimental built-in `defender` allows you to configure an auto-blocking policy for SFTPGo and thus helps to prevent DoS (Denial of Service) and brute force password guessing.

If enabled it will protect SFTP, FTP and WebDAV services and it will automatically block hosts (IP addresses) that continually fail to log in or attempt to connect.

You can configure a score for each event type:

- `score_valid` defines the score for valid login attempts, eg. user accounts that exist. Default `1`.
- `score_invalid` defines the score for invalid login attempts, eg. non-existent user accounts or client disconnected for inactivity without authentication attempts. Default `2`.

And then you can configure:

- `observation_time` defines the time window, in minutes, for tracking client errors.
- `threshold` defines the threshold value before banning a host.
- `ban_time` defines the time to ban a client, as minutes

So a host is banned, for `ban_time` minutes, if it has exceeded the defined threshold during the last observation time minutes.

A banned IP has no score, it makes no sense to accumulate host events in memory for an already banned IP address.

If an already banned client tries to log in again its ban time will be incremented based on the `ban_time_increment` configuration.

The `ban_time_increment` is calculated as percentage of `ban_time`, so if `ban_time` is 30 minutes and `ban_time_increment` is 50 the host will be banned for additionally 15 minutes. You can specify values greater than 100 for `ban_time_increment`.

The `defender` will keep in memory both the host scores and the banned hosts, you can limit the memory usage using the `entries_soft_limit` and `entries_hard_limit` configuration keys.

The REST API allows:

- to retrieve the score for an IP address
- to retrieve the ban time for an IP address
- to unban an IP address

We don't return the whole list of the banned IP addresses or all the stored scores because we store them as hash map and iterating over all the keys for an hash map is slow and will slow down new events registration.

The `defender` can also load a permanent block list and/or a safe list of ip addresses/networks from a file:

- `safelist_file`, string. Path to a file with a list of ip addresses and/or networks to never ban.
- `blocklist_file`, string. Path to a file with a list of ip addresses and/or networks to always ban.

These list must be stored as JSON with the following schema:

- `addresses`, list of strings. Each string must be a valid IPv4/IPv6 address.
- `networks`, list of strings. Each string must be a valid IPv4/IPv6 CIDR address.

Here is a small example:

```json
{
    "addresses":[
        "192.0.2.1",
        "2001:db8::68"
    ],
    "networks":[
        "192.0.2.1/24",
        "2001:db8:1234::/48"
    ]
}
```

These list will be loaded in memory for faster lookups. The REST API queries "live" data and not these lists.

The `defender` is optimized for fast and time constant lookups however as it keeps all the lists and the entries in memory you should carefully measure the memory requirements for your use case.
