# Metrics

SFTPGo exposes [Prometheus](https://prometheus.io/) metrics at the `/metrics` HTTP endpoint of the telemetry server.
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
- Go's runtime details about GC, number of gouroutines and OS threads
- Process information like CPU, memory, file descriptor usage and start time

Please check the `/metrics` page for more details.

We expose the `/metrics` endpoint in both HTTP server and the telemetry server, you should use the one from the telemetry server. The HTTP server `/metrics` endpoint is deprecated and it will be removed in future releases.
