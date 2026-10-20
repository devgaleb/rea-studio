# REA Studio — Reverse Engineering Workbench Update

This release adds provider-backed evidence export and a Windows desktop packaging path. The UI only displays provider findings when a real analysis job returns them; it does not invent disassembly or AI conclusions.

## New capabilities

- **Ghidra:** headless import/analysis with exported decompiler output, function entry/end addresses, instruction text/addresses, incoming references, call targets, and basic-block successor edges.
- **IDA Pro:** batch adapter using `idat`/`idat64`/`ida64` with `-A -S`. It exports decompilation when Hex-Rays is available, instruction addresses, calls, and xrefs. Use only a properly licensed installation; headless flags vary by IDA version and platform.
- **Function evidence viewer:** choose a function returned by the provider and inspect its decompilation, calls, instructions, and basic-block successor list. This is a CFG edge listing, not a graph layout canvas.
- **Android/JADX:** decodes through JADX, inventories the decoded manifest's permissions and common components, and records Java files with method-name candidates. Manifest evidence is shown with its output path; this is not a full semantic Android parser.
- **Evidence discipline:** provider outputs retain addresses, names, instruction evidence, and tool artifacts. Any future AI explanation must be generated from these records and cite them; no AI service is silently called by this release.
- **Windows desktop scaffold:** Electron wrapper, isolated preload, per-launch local bridge token, and NSIS installer configuration.

## Run in browser mode

1. Start `local-service/start-bridge.bat` (Python 3.10+).
2. Serve the `rea-studio` directory from `http://127.0.0.1:8080` (for example `python -m http.server 8080`).
3. Open that address, choose Engine & Providers, paste the token printed by the service, test the connection, and configure provider paths.

## Build Windows desktop installer

Requires Windows, Node.js, npm, and Python 3.10+. First run `desktop/build-bridge-windows.bat` to build the Python bridge executable (PyInstaller). Then:

```powershell
cd desktop
npm install
npm run dist:win
```

The installer is written to `desktop/dist/`. For a source-only run, use `npm start`; Python must be installed and available as `py -3`.

## Important verification status

The package is source-scaffolded, not a signed or Windows-tested installer. Actual Ghidra/IDA/JADX jobs require those providers installed and correctly configured. IDA command-line behaviour and Hex-Rays availability depend on the licensed version. Android parsing is based on JADX's decoded output and should be reviewed against the source artifact. Control-flow blocks are address/successor evidence rather than a rendered graph. An OpenAI-compatible Chat Completions endpoint can be configured through `REA_AI_BASE_URL`, `REA_AI_API_KEY`, and `REA_AI_MODEL` before launching the bridge. The app sends only the selected function evidence and question to that configured endpoint; do not set these variables if you do not want code evidence sent to an external AI provider. No AI provider is called by default.

## Optional evidence-backed AI

Set `REA_AI_BASE_URL` to the API base URL (for example, a provider endpoint ending in `/v1`), `REA_AI_API_KEY` to your secret key, and `REA_AI_MODEL` to the exact model identifier, then restart the bridge. The UI will send the selected function’s decompilation, instructions, call targets, and basic blocks to `/api/explain`. Responses are instructed to cite addresses and separate observations from inference. Verify citations manually; prompting is not a guarantee of correctness. Never place API keys in the browser UI or commit them to source control.

## Safety

The bridge binds to loopback and requires a random bearer token. It launches allowlisted provider executables without a shell. Analyse only files you are authorized to inspect; prefer an isolated VM for unknown binaries. Keep the bridge token private.
