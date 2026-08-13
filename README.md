# AI Scanner

Cross-platform process telemetry and AI-assisted threat triage for Windows, Linux, and macOS.

AI Scanner listens to running processes for a selected period, performs the expensive correlation locally, removes low-value noise, stores the evidence on disk, and creates a ready-to-paste prompt for Codex or another AI. The AI interprets a prepared evidence package—it is not asked to collect or invent telemetry.

![AI Scanner neon desktop interface](docs/screenshots/aiscanner-main.jpg)

## Install in one command

The release packages are self-contained; you do **not** need to install .NET or build the source code.

### Windows 10/11 x64

Open **PowerShell**, paste this line, and press Enter:

```powershell
irm https://raw.githubusercontent.com/Teknesyum/AiScanner/main/scripts/install.ps1 | iex
```

The installer downloads the latest release, installs it under `%LOCALAPPDATA%\Programs\AiScanner`, creates an **AI Scanner** desktop shortcut with the application icon, and launches the app. Run PowerShell as Administrator when you want Windows ETW upload/download byte telemetry; the rest of the scanner also works without elevation.

### Linux x64

Open a terminal, paste this line, and press Enter:

```bash
curl -fsSL https://raw.githubusercontent.com/Teknesyum/AiScanner/main/scripts/install-linux.sh | bash
```

The installer places the application in `~/.local/share/AiScanner`, creates the `aiscanner` command and adds **AI Scanner** to the desktop application menu. On a graphical session it launches the app automatically. No `sudo` is required.

If your minimal Linux installation does not already contain desktop libraries, install them once:

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y libx11-6 libice6 libsm6 libfontconfig1
```

You can then launch it from the application menu or run:

```bash
aiscanner
```

### macOS — Intel and Apple Silicon

Open **Terminal**, paste this line, and press Enter. The installer automatically selects Intel (`x64`) or Apple Silicon (`arm64`):

```bash
curl -fsSL https://raw.githubusercontent.com/Teknesyum/AiScanner/main/scripts/install-macos.sh | bash
```

The app is installed as `~/Applications/AI Scanner.app` and opened automatically. The current package is not Apple-notarized. If macOS blocks the first launch, open **Finder → Home → Applications**, Control-click **AI Scanner**, choose **Open**, then confirm **Open**. This approval is normally needed only once.

### Updating

Run the same one-line installer again. It downloads the newest GitHub release and replaces the existing installation while keeping locally collected analysis data.

## What it detects

- CPU and memory behavior over time—not just a single snapshot
- executable path, creation time, SHA-256 identity, and platform signature status
- established remote endpoints attributed to individual processes
- sustained load, sharp CPU changes, recent binaries, writable-path execution, PID respawning, and signature/network combinations
- Windows Task Manager evasion patterns, where high load drops immediately after Task Manager starts
- abnormal upload/download behavior when the platform exposes per-process byte telemetry

Pressing **Scan now** creates an instant evidence set and enables the prompt button. Pressing **1, 5, 10, 20, or custom minutes** starts a new capture at that exact moment. AI Scanner samples throughout the full interval, shows the countdown in the scan control, writes JSONL locally, creates a correlated JSON bundle, and only then enables the AI prompt.

## Platform capabilities

| Capability | Windows | Linux | macOS |
|---|---|---|---|
| Process, CPU, RAM, path, hash | Yes | Yes, subject to `/proc` permissions | Yes, subject to OS permissions |
| Code signature verification | Authenticode chain | Reported unavailable; never treated as unsigned | `codesign --verify` |
| Established TCP endpoints | IP Helper API | `/proc/net/tcp*` + socket inode/PID mapping | `lsof` |
| Per-process upload/download bytes | ETW when elevated | Unavailable without a privileged eBPF collector | Unavailable without an entitled Network Extension |
| Task Manager evasion signal | Yes | Not applicable | Not applicable |

Missing telemetry is recorded as **unavailable**, never as zero activity or evidence of safety.

## Local data and AI workflow

Data is stored under the operating system's local application-data directory in `AiScanner/data`. The generated prompt contains the exact analysis bundle path, explains its schema, marks unavailable capabilities, and asks the AI to produce an evidence-based report. The app never uploads data by itself, kills processes, deletes files, or quarantines software.

AI Scanner is a triage and investigation aid, not a replacement for antivirus/EDR or professional incident response.

## Build from source

Requires the .NET 9 SDK:

```powershell
dotnet test AiScanner.sln -c Release
dotnet run --project src/AiScanner.App/AiScanner.App.csproj
```

Create self-contained Windows x64, Linux x64, macOS x64, and macOS ARM64 archives:

```powershell
./scripts/build-release.ps1 -Version 0.3.1
```

The desktop UI uses [Avalonia](https://avaloniaui.net/). Windows network-byte collection uses ETW; Linux and macOS adapters use native, read-only operating-system sources.

## Privacy and responsible use

- no automatic upload or cloud dependency
- user-profile paths are anonymized in compact AI summaries
- executable metadata is treated as untrusted input
- no destructive remediation actions
- only scan systems you own or are authorized to inspect

## Sponsor

If AI Scanner saves you time, you can support continued development:

[![Sponsor Teknesyum](https://img.shields.io/badge/Sponsor-Teknesyum-ff00ff?style=for-the-badge&logo=githubsponsors&logoColor=white)](https://github.com/sponsors/Teknesyum)

## Author and license

Created and maintained by [Teknesyum](https://github.com/Teknesyum). Source code is licensed under the [MIT License](LICENSE).
