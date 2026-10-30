# Slowport

A small Windows-friendly, rate-limited TCP connect scanner for authorized network assessments. Uses the Go standard library; no administrator privileges required.

## Build

Install Go 1.22 or later, then run in this directory:

```powershell
go test ./...
go build -trimpath -o slowport.exe .
```

## Use

Scan only systems you own or have permission to assess. Both targets and an explicit authorization allowlist are required. DNS results are checked against the allowlist before connections start.

```powershell
# Local example
.\slowport.exe --targets 127.0.0.1 --allow 127.0.0.1 --ports 22,80,443

# Authorized lab subnet; exclude a sensitive host
.\slowport.exe --targets 192.168.56.0/28 --allow 192.168.56.0/24 --exclude 192.168.56.1 --ports 22,80,443,8000-8010 --interval 10s --timeout 2s
```

Defaults: one connection at a time, a five-second delay before each attempt, a two-second connection timeout, and a limit of 256 targets. The delay begins after the preceding attempt and checkpoint write finish. The minimum permitted delay is one second. CIDRs include every address, including IPv4 network and broadcast addresses; exclude those explicitly when needed. Large CIDR expansions are rejected before iteration. IPv6 literals and bounded IPv6 CIDRs are supported; scoped/link-local zone identifiers are unsupported.

The scanner performs ordinary TCP connection handshakes and closes successful connections immediately. It sends no application payloads. It uses normal DNS resolution for hostname targets. Activity is visible to network and endpoint monitoring. Enterprise deployment can use your normal code-signing and application allowlisting processes.

## Pause and resume

Press **Ctrl+C** to pause. Completed attempts are saved to `slowport-state.json` after every probe; CSV is written on graceful interruption and completion. Resume with the same scope and ports:

```powershell
.\slowport.exe --targets 127.0.0.1 --allow 127.0.0.1 --ports 22,80,443 --resume
```

For a new scan, choose a new `--state` and `--csv` path. An existing checkpoint is protected from accidental reuse unless `--resume` is supplied. Existing CSV output is replaced. Keep checkpoint files trusted and unedited; they determine which attempts are skipped. Only run one process per checkpoint/output pair. An abrupt shutdown can repeat an attempt that completed before its checkpoint was saved. Resume resolves hostnames again and rejects changed destination sets.

## Results

JSON contains the destination set, ports and timestamped results. CSV contains `address,port,status,detail,time`.

| Status | Meaning |
| --- | --- |
| `open` | TCP connection succeeded at that time |
| `timeout` | Connection attempt timed out |
| `error` | Connection failed; detail records the operating-system error |

A failure or timeout alone does not establish that a port is closed or filtered. Scan results are observations, not vulnerability findings. Output and checkpoints contain network inventory information; store and share them accordingly.
