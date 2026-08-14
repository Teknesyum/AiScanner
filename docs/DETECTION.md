# Detection reference

ProcWitness findings prioritize investigation; no individual finding proves malicious activity. Missing platform telemetry is marked unavailable and never treated as zero or as evidence of safety.

| Code | Weight | Trigger | Common benign explanations |
|---|---:|---|---|
| `unsigned` | 15 | Signature verification is available but the executable has no verifiable publisher signature. | Internal tools, open-source utilities, development builds. |
| `user-writable-path` | 15 | The executable runs from a temporary or user application-data directory. | Per-user installers, chat clients, launchers, portable applications. |
| `elevated-cpu` | 10 | Current normalized CPU usage is at least 35%. | Compilation, games, media encoding, updates. |
| `high-cpu` | 20 | Current normalized CPU usage is at least 70%. | Rendering, stress tests, compression, scientific workloads. |
| `hidden-load` | 10 | CPU is at least 35% and no visible window is available. | Services, background workers, tray applications. |
| `unsigned-network` | 20 | An unsigned process has one or more established remote connections. | Locally built network tools and unsigned portable clients. |
| `recent-network-binary` | 15 | A binary created within seven days has an active connection. | Fresh installs and automatic updates. |
| `background-upload` | 20 | A process without a visible window has sent at least 10 MB. | Backup, synchronization, telemetry, game launchers. |
| `taskmgr-evasion` | 30 | Average CPU of at least 30% falls to 5% or one fifth after Task Manager starts. | Work completing naturally or software reacting benignly to system load. |

Windowed captures also summarize sustained CPU, CPU range, sent and received deltas, recent binaries, hidden load, and PID reuse. These correlations reduce noise but must still be checked against executable path, SHA-256, publisher, role, and the complete timeline.
