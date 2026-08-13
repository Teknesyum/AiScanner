# AI Scanner

![AI Scanner live process telemetry dashboard](docs/screenshots/aiscanner-main.jpg)

AI Scanner is a local-first process telemetry and behavioral threat-analysis tool for Windows.

It watches running processes over time instead of judging them from a single Task Manager snapshot. CPU and memory trends, executable identity, SHA-256 hashes, signature trust, file age, visible-window state, active remote endpoints, and per-process TCP/IP traffic are correlated to surface behavior associated with cryptominers, spyware, suspicious background upload, newly installed network-active binaries, and processes that reduce their workload when Task Manager opens.

AI Scanner performs collection, filtering, scoring, and time-window analysis locally. AI is optional and is used only after the local engine has prepared a focused evidence package. It does not receive an unfiltered process dump and is not responsible for collecting the data.

## Install with one PowerShell command

Open PowerShell and run:

```powershell
irm https://raw.githubusercontent.com/Teknesyum/AiScanner/main/scripts/install.ps1 | iex
```

The installer downloads the latest self-contained Windows x64 release, installs it to `%LOCALAPPDATA%\Programs\AiScanner`, creates an icon-enabled **AI Scanner** desktop shortcut, and launches the application. The .NET SDK is not required.

AI Scanner requests administrator privileges because accurate per-process TCP/IP byte accounting uses kernel ETW events.

## What AI Scanner does

- Captures process ID, name, executable path, start time, CPU usage, working set, and visible-window state.
- Calculates SHA-256 hashes so the same executable can be followed across PID changes and restarts.
- Validates executable certificate chains and records the publisher without treating a signature as automatic proof of safety.
- Tracks active remote TCP endpoints and real sent/received byte counters per process through ETW.
- Detects unsigned network-active processes, recent binaries with network activity, hidden high-load processes, and background upload.
- Correlates Task Manager startup with sudden CPU reductions to identify possible monitor-aware miner behavior.
- Runs fresh 1, 5, 10, 20, or custom-minute capture sessions. A session starts when the button is pressed and is analyzed only after its timer finishes.
- Filters stable low-impact processes while retaining low-CPU processes that have network, signature, file-age, or restart risk signals.
- Produces a readable local report, a guided JSON evidence bundle, and an AI-ready interpretation prompt.
- Opens the selected process executable directly in File Explorer for manual investigation.

## Behavioral analysis model

AI Scanner uses two related analysis layers.

### Live scoring

The live table scores explainable signals such as:

- unsigned executable;
- execution from user-writable or temporary directories;
- elevated or very high CPU usage;
- high CPU without a visible window;
- unsigned executable with an active remote connection;
- recently created executable with network activity;
- high background upload;
- a sharp CPU reduction after Task Manager starts.

Scores are capped at 100 and mapped to Clean, Low, Medium, High, or Critical. A high score is an investigation priority, not a malware verdict.

### Timed sessions

When a timed capture is started, AI Scanner records a new isolated observation window. It calculates average/peak/range CPU, peak memory, upload/download deltas, remote endpoints, PID reuse, file age, trust state, and meaningful timeline milestones. Only data captured by that running application instance and inside the exact start/end timestamps is included.

Stable processes are omitted unless at least one meaningful condition exists, including a CPU peak, a material CPU swing, upload/download activity, an unsigned network connection, a recent executable, or multiple PIDs for the same file identity.

## AI-assisted reporting

After a timed session completes, **Create analysis prompt** becomes available. It creates:

- a human-readable local report;
- an indexed JSON bundle with locally calculated scores and findings;
- a prompt instructing Codex or a local AI to interpret the prepared evidence rather than recollect or blindly filter raw telemetry.

If static inspection is required, the AI report can identify the exact executable path and SHA-256 and ask the user to upload that specific file. No executable is uploaded automatically.

## Privacy and safety

- Telemetry remains local unless the user deliberately shares an analysis bundle.
- User-profile paths are anonymized as `%USERPROFILE%` in AI bundles.
- Process metadata is treated as untrusted data in the generated prompt.
- AI Scanner does not terminate processes, delete files, quarantine executables, or change security settings.
- Missing network telemetry is reported as missing evidence; zero is not treated as proof of no activity.
- AI Scanner is an investigation and early-warning tool, not a replacement for antivirus or professional incident response.

## Data locations

Application telemetry and analysis bundles are stored under:

```text
%LOCALAPPDATA%\AiScanner\data
```

The rolling telemetry file is `telemetry.jsonl`. During normal monitoring it is persisted every 15 seconds; during an active timed session every live scan is retained. At 256 MB, records older than seven days are compacted.

## Requirements

- Windows 10 or Windows 11, x64.
- Administrator approval for kernel network telemetry.
- PowerShell 5.1 or newer for installation.

## Uninstall

```powershell
& "$env:LOCALAPPDATA\Programs\AiScanner\uninstall.ps1"
```

Telemetry under `%LOCALAPPDATA%\AiScanner` is retained so uninstalling the application does not silently delete investigation data.

## Build from source

Requirements: Windows and the .NET 9 SDK.

```powershell
git clone https://github.com/Teknesyum/AiScanner.git
cd AiScanner
dotnet restore
dotnet test
dotnet run --project src\AiScanner.App\AiScanner.App.csproj
```

## License

AI Scanner is released under the [MIT License](LICENSE).

---

## Support

This application is built in spare time and is free.

<a href="https://github.com/sponsors/Teknesyum"><img src="https://img.shields.io/badge/Buy_me_a_coffee-b026ff?style=for-the-badge&logo=githubsponsors&logoColor=b026ff&labelColor=0d0d0f" alt="Sponsor" /></a>

**[github.com/Teknesyum](https://github.com/Teknesyum)** · [MIT](LICENSE)
