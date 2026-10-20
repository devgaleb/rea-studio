# REA Studio — Native Analysis Workbench

REA Studio combines browser-local triage with an optional loopback-only bridge for real native analysis. The bridge can launch configured **Ghidra headless analysis** and **JADX decompilation** as actual subprocesses, track jobs, request cancellation, and retain tool logs/output locally. IDA path detection is informational only; a licensed IDA adapter is not included.

## Quick start

1. Install Python 3.10+.
2. Start the bridge from `local-service/`: Windows: double-click `start-bridge.bat`; macOS/Linux: run `./start-bridge.sh`.
3. Copy the bearer token printed in the terminal. Keep it private.
4. Serve this directory on the same machine: `python -m http.server 8080`.
5. Open `http://127.0.0.1:8080` and load a file.
6. Open **Engine & providers**, paste the token, and select **Test connection**.
7. Set the Ghidra `analyzeHeadless` and/or JADX executable paths, choose **Save preferences**, then **Save provider paths to bridge**.
8. Use **Analyze loaded file with Ghidra** or **Decompile loaded APK/DEX with JADX**. View job state, output logs and generated files in the bridge's local data directory.

The browser page must be served from `http://127.0.0.1:8080` for the bridge's CORS policy. The bridge binds only to `127.0.0.1:8765`. It accepts no arbitrary shell command, limits uploads to 100 MiB, applies time limits, and requires a bearer token. Do not expose the port through a proxy or bind it to a public interface.

## Provider setup

- **Ghidra:** install a supported Ghidra distribution and Java runtime. Configure the full path to `support/analyzeHeadless.bat` on Windows or `support/analyzeHeadless` on macOS/Linux. The bridge imports and analyzes the artifact and invokes `local-service/ghidra_scripts/ExportFunctions.java` to export function names, entry addresses, signatures, and decompiler output when Ghidra can decompile them. Ghidra's headless analyzer supports import, analysis and scripted processing: [official guide](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md).
- **JADX:** install JADX and configure the full path to `jadx.bat`/`jadx` (or an executable launcher). It decompiles Android DEX/APK and Java archive formats and decodes Android resources where supported: [official project](https://github.com/skylot/jadx).
- **IDA:** path field is reserved for a future provider adapter. This package does not claim to control IDA or bypass its license.
- **REA engine:** the original `../rea-main/` source remains intact. Its CLI and provider configuration are version-dependent; run its own documented commands from that directory. The bridge does not guess undocumented REA CLI invocations.

## Local output

Jobs are stored under `~/.rea-studio/jobs/` by default (override with `REA_STUDIO_DATA`). Each job keeps its input copy, tool logs, and generated outputs. Treat output as potentially sensitive. Remove the data directory when no longer needed. A failed or timed-out job is not evidence that the file is benign.

## Security and limitations

- Only analyze files you own or are authorized to assess.
- Inputs are copied to a local job directory and are never intentionally sent to a remote service by this bridge.
- External tools parse untrusted inputs; use an isolated VM/container for suspicious artifacts.
- The bridge requires a token but is intended for a single trusted local user, not multi-user deployment.
- Cancellation is best-effort and terminates the active process; descendants may require OS-level cleanup on some platforms.
- Job progress is estimated from process output, not an exact percentage from Ghidra/JADX.
- IDA integration, AI explanations, CFG rendering, and a signed Windows installer are not included in this bridge build.

## Existing browser modules

Binary signatures, SHA-256, printable strings, hex preview, heuristic indicators, ZIP/APK inventory, and JSON/CSV reports continue to work without the bridge. The browser triage output remains heuristic; provider-backed evidence should be treated separately and validated.
