# CLAUDE.md

## Builds and tests

Run builds and tests through `scripts/offload`, e.g.
`scripts/offload go test ./internal/...` or `scripts/offload go build -o gonas .`.
It syncs the working tree to the faster desktop PC (ssh host `pc`) and runs the
command there, falling back to a local run when the PC is offline. Its output
says which one happened. Build output (like the `gonas` binary) stays on the
machine that ran the command.

Locally, Go lives in `~/sdk/go/bin`, which may not be on `PATH`.
