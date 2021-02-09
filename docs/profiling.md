# Profiling SFTPGo

The built-in profiler lets you collect CPU profiles, traces, allocations and heap profiles that allow to identify and correct specific bottlenecks.
You can enable the built-in profiler using `telemetry` configuration section inside the configuration file.

Profiling data are exposed via HTTP/HTTPS in the format expected by the [pprof](https://github.com/google/pprof/blob/main/doc/README.md) visualization tool. You can find the index page at the URL `/debug/pprof/`.

The following profiles are available, you can obtain them via HTTP GET requests:

- `allocs`, a sampling of all past memory allocations
- `block`, stack traces that led to blocking on synchronization primitives
- `goroutine`, stack traces of all current goroutines
- `heap`, a sampling of memory allocations of live objects. You can specify the `gc` GET parameter to run GC before taking the heap sample
- `mutex`, stack traces of holders of contended mutexes
- `profile`, CPU profile. You can specify the duration in the `seconds` GET parameter. After you get the profile file, use the `go tool pprof` command to investigate the profile
- `threadcreate`, stack traces that led to the creation of new OS threads
- `trace`, a trace of execution of the current program. You can specify the duration in the `seconds` GET parameter. After you get the trace file, use the `go tool trace` command to investigate the trace

For example you can:

- download a 30 seconds CPU profile from the URL `/debug/pprof/profile?seconds=30`
- download a sampling of memory allocations of live objects from the URL `/debug/pprof/heap?gc=1`
- download a sampling of all past memory allocations from the URL `/debug/pprof/allocs`
