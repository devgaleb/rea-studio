# REA Studio — Final Workbench Upgrade

This update adds two substantive local analysis modules while preserving the existing `rea-main/` engine source.

## New capabilities

- **Android / APK explorer:** indexes ZIP central-directory records, lists archive paths and sizes, detects `AndroidManifest.xml`, `classes*.dex`, native `.so` libraries, and resource paths, and exports a JSON inventory.
- **Analysis jobs:** provides a visible job queue with progress, cancellation, status, timestamps, and actual browser-local SHA-256 verification, string extraction, and ZIP/APK inventory tasks.
- **Binary evidence:** reports Shannon entropy as a triage clue, alongside existing hashes, magic-byte format hints, and extracted strings.
- **Evidence report v2:** adds entropy and container-entry counts to the exported report.
- **Safer boundaries:** jobs never execute uploaded files or arbitrary shell commands. Native Ghidra/IDA decompilation is not represented as available unless a separately implemented local desktop adapter is connected.

## Run

Open `rea-studio/index.html` in a modern browser. For best browser cryptography support, serve the folder from localhost rather than opening it as a `file://` URL. No files are uploaded by these browser modules.

## Limitations

- The APK explorer reads ZIP metadata only; it does not decompress entries or decode binary Android XML, resources tables, or DEX bytecode.
- Browser job progress is for the actual local tasks listed in the job queue, not a claim that a native REA/Ghidra/IDA workflow is running.
- High entropy is ambiguous and is not a malware verdict.
- Large files consume browser memory; the existing 250 MB guard remains in place.

## Next native integration boundary

For genuine decompilation, add a separately packaged desktop/local service with loopback-only binding, per-session authentication, strict path allowlists, bounded output, cancellation, provider capability checks, and structured evidence results. Do not expose arbitrary shell execution to the UI.
