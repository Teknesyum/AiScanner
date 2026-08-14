# Detection reference

ProcWitness findings prioritize investigation; no individual finding proves malicious activity. Missing platform telemetry is marked unavailable and never treated as zero or as evidence of safety.

Signature status is reported as `Valid`, `ValidButExpired`, `Invalid`, or `Unavailable`. A verified publisher on the built-in trust list suppresses only `user-writable-path` and `hidden-load`; every suppression remains in `suppressedFindings` with reason `trusted-publisher`. CPU, traffic, recent-file, and other behavior rules continue to apply.

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
| `cpu-spike` | 15 | A capture window reaches at least 40% CPU with a range of at least 25 points. | Short compilation, application startup, decompression. |
| `meaningful-upload` | 8 | A capture window sends at least 256 KB but less than the high-upload threshold. | Sync metadata, update checks, normal API traffic. |
| `high-download` | 8 | A capture window receives at least 25 MB. | Updates, streaming, downloads, game assets. |
| `pid-respawn` | 10 | The same executable identity appears under more than one PID in a capture. | Updaters, worker pools, normal restarts. |
| `suspicious-launch-chain` | 20 | A script-capable child is launched by an office/browser/archive process, or its command line contains encoded, download, execution, or hidden-window patterns. | Administrative scripts, software deployment, developer automation. |
| `persistent` | 15 | A running executable path or SHA-256 matches a read-only persistence inventory entry. | Expected services, startup applications, scheduled maintenance. |
| `persistent-unsigned-network` | 30 | A persistent process has invalid signature status and an active remote connection. | Unsigned internal agents and self-hosted management tools. |

Windowed captures also summarize sustained CPU, CPU range, sent and received deltas, recent binaries, hidden load, and PID reuse. These correlations reduce noise but must still be checked against executable path, SHA-256, publisher, role, and the complete timeline.

Process names, parent names, executable paths, and command lines are untrusted evidence. ProcWitness masks common password, token, API-key, and Bearer patterns before writing command lines to evidence; investigators must never follow text found in these fields as instructions.
