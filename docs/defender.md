# Defender

The built-in `defender` allows you to configure an auto-blocking policy for SFTPGo and thus helps to prevent DoS (Denial of Service) and brute force password guessing.

If enabled it will protect SFTP, HTTP (WebClient and user API), FTP and WebDAV services and it will automatically block hosts (IP addresses) that continually fail to log in or attempt to connect.

You can configure a score for the following events:

- `score_valid`, defines the score for valid login attempts, eg. user accounts that exist. Default `1`.
- `score_invalid`, defines the score for invalid login attempts, eg. non-existent user accounts. Default `2`.
- `score_no_auth`, defines the score for clients disconnected without any authentication attempt. Default `0`.
- `score_limit_exceeded`, defines the score for hosts that exceeded the configured rate limits or the configured max connections per host. Default `3`.

You can set the score to `0` to not penalize some events.

And then you can configure:

- `observation_time`, defines the time window, in minutes, for tracking client errors.
- `threshold`, defines the threshold value before banning a host.
- `ban_time`, defines the time to ban a client, as minutes

So a host is banned, for `ban_time` minutes, if the sum of the scores has exceeded the defined threshold during the last observation time minutes.

By defining the scores, each type of event can be weighted. Let's see an example: if `score_invalid` is 3 and `threshold` is 8, a host will be banned after 3 login attempts with an non-existent user within the configured `observation_time`.

A banned IP has no score, it makes no sense to accumulate host events in memory for an already banned IP address.

If an already banned client tries to log in again, its ban time will be incremented according the `ban_time_increment` configuration.

The `ban_time_increment` is calculated as percentage of `ban_time`, so if `ban_time` is 30 minutes and `ban_time_increment` is 50 the host will be banned for additionally 15 minutes. You can also specify values greater than 100 for `ban_time_increment` if you want to increase the penalty for already banned hosts.

SFTPGo can store host scores and banned hosts in memory or within the configured data provider according to the `driver` set in the `defender` configuration section. The available drivers are `memory` and `provider`.
The `provider` driver is useful if you want to share the defender data across multiple SFTPGo instances and it requires a shared or distributed data provider: `MySQL`, `PostgreSQL` and `CockroachDB` are supported.
If you set the `provider` driver, the defender implementation may do many database queries (at least one query every time a new client connects to check if it is banned), if you have a single SFTPGo instance the `memory` driver is recommended.

For the `memory` driver, you can limit the memory usage using the `entries_soft_limit` and `entries_hard_limit` configuration keys.

The `provider` driver will periodically clean up expired hosts and events.

Using the REST API you can:

- list hosts within the defender's lists
- remove hosts from the defender's lists

The `defender` can also check permanent block and safe lists of IP addresses/networks. You can define these lists using the WebAdmin UI or the REST API. In multi-nodes setups, the list entries propagation between nodes may take some minutes.
