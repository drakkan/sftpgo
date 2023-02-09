# Metrics

SFTPGo supports [Prometheus](https://prometheus.io/) metrics at the `/metrics` HTTP endpoint of the telemetry server.
Several counters and gauges are available, for example:

- Total uploads and downloads
- Total upload and download size
- Total upload and download errors
- Total executed SSH commands
- Total SSH command errors
- Number of active connections
- Data provider availability
- Total successful and failed logins using password, public key, keyboard interactive authentication or supported multi-step authentications
- Total HTTP requests served and totals for response code
- Go's runtime details about GC, number of goroutines and OS threads
- Process information like CPU, memory, file descriptor usage and start time

Please check the `/metrics` page for more details.

The telemetry server is disabled by default in the released [sftpgo.json](https://raw.githubusercontent.com/drakkan/sftpgo/main/sftpgo.json). To enable look in [docs/full-configuration.md](https://raw.githubusercontent.com/drakkan/sftpgo/main/docs/full-configuration.md) for configuration details.
