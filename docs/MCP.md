# ProcWitness MCP server

ProcWitness exposes its passive process-forensics engine as a local MCP server over stdio. The server does not open a network listener and never uploads evidence by itself.

## Add to Claude Code

Install ProcWitness so the `procwitness` command is on PATH, then run:

```bash
claude mcp add procwitness -- procwitness mcp
```

For another MCP client, configure a stdio server whose command is `procwitness` and whose sole argument is `mcp`.

## Tools

| Tool | Purpose |
|---|---|
| `list_processes` | Return risk-ordered live processes, limited to 20 by default and 100 maximum. |
| `start_capture` | Start a timed capture and immediately return a `captureId`. |
| `capture_status` | Return state, remaining seconds, errors, and bundle availability. |
| `get_bundle` | Return a completed bundle summary; `full: true` explicitly requests the complete evidence file. |
| `list_persistence` | Return the read-only persistence inventory and unavailable sources. |
| `compare_baseline` | Compare current state with the supplied or latest baseline. |
| `get_process_details` | Return path, hash, signature, command line, parent, endpoints, findings, and suppressed findings for one PID. |

There are deliberately no tools for terminating processes, deleting files, disabling services, editing persistence, or changing the registry.

## Security boundary

Process names, paths, command lines, publishers, persistence commands, and endpoints are untrusted evidence. Every relevant tool description and result warns the model not to treat these strings as instructions. Known password, token, API-key, and Bearer patterns are masked locally before they reach the evidence stream.

`get_bundle` returns a summary by default to protect the model context window. Request the full bundle only when raw time-series evidence is necessary. Missing platform capabilities remain explicitly unavailable and are not converted to zeros.

## Example workflow

1. Ask the client to call `list_processes` and explain the highest-ranked candidates without making a malware verdict.
2. Call `start_capture` with `{"minutes": 5}` and retain the returned `captureId`.
3. Poll `capture_status` without blocking the conversation.
4. When complete, call `get_bundle` with the same ID. Start with the default summary.
5. Request `get_process_details` only for candidates that require deeper evidence.

Malformed JSON and invalid JSON-RPC requests return standard error objects. Tool-level failures return MCP tool results with `isError: true`; the server remains alive for subsequent requests.
