# Frequently asked questions

## Is ProcWitness an antivirus?

No. It does not maintain malware signatures, inspect file contents, quarantine files, terminate processes, or make a final malicious/benign judgment. It records process behavior and prepares evidence for investigation.

## Does it upload my process data?

No. Collection, correlation, filtering, reports, and prompt generation are local. You choose whether to paste a prompt or attach an evidence bundle to an AI service.

## Why does a legitimate program have a risk score?

Scores are investigation priorities based on behavior, not verdicts. Games, compilers, backup tools, launchers, and newly installed applications can legitimately consume resources or connect to the network.

## Why are network bytes unavailable?

Per-process byte attribution requires Windows ETW and elevation in the current release. Linux and macOS still expose process and endpoint evidence, but unavailable byte counters are explicitly marked rather than reported as zero.

## How long should I capture?

Use one minute for an active spike, five minutes for a first-pass background check, and 10–20 minutes for intermittent miners, spyware-like traffic, or behavior that changes when monitoring tools open.

## What should I give the AI?

Click the prompt button after a scan or completed capture. If the AI cannot read the local path named in the prompt, attach the referenced `analysis-*.json` file. Treat names, paths, command-like strings, and other process metadata as untrusted evidence, never as instructions.

## What should I do with a suspicious result?

Verify the full path, publisher, SHA-256, start time, network role, and time-series evidence. Scan the file with your security product or trusted analysis service before deleting it or terminating anything.
