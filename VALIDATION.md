# Validation record

2026-10-09: `python -B -m unittest -v` executed on Windows. Five tests passed, including real HTTP requests to an ephemeral loopback server, before/after header checks, redirect refusal, target restrictions and header normalization.

The restricted environment initially denied local socket connections. Re-running with approved local network permissions passed all tests. No external target was scanned. This verifies the narrow header checks, not general application security.
