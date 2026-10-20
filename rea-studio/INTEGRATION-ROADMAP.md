# REA Studio + REA Engine: integration roadmap

## Architecture

- **Engine (`rea-main/`)**: existing REA CLI, MCP server, agent workflows, analysis bridges, and test infrastructure.
- **Studio (`rea-studio/`)**: local-first visual intake and static artifact triage.
- **Adapter (next implementation)**: narrow local service that invokes only documented REA commands and returns structured, bounded results.

## Recommended next milestones

1. **Command discovery:** call the existing `rea --help` / documented CLI contracts; do not hard-code unverified command names.
2. **Adapter API:** `GET /health`, `GET /capabilities`, `POST /analysis-jobs`, `GET /analysis-jobs/:id`, `POST /analysis-jobs/:id/cancel`. Bind to loopback only, protect with a per-session token, and reject arbitrary shell strings.
3. **Job safety:** allowlist operations, validate file paths, set timeouts and output caps, record tool versions, and support cancellation.
4. **Engine integration:** route supported artifact types to existing REA workflows; return findings with source evidence, offsets/addresses, confidence, and limitations.
5. **Native analysis:** detect configured Ghidra/IDA/Hopper providers and clearly explain when a provider is missing. Do not silently install tools.
6. **Desktop packaging:** package the UI with Electron or Tauri; use a restrictive CSP, no remote navigation, no Node integration in renderer, and a minimal preload bridge.
7. **Quality:** test malformed/empty/large files, filename edge cases, hash/report stability, cancellation, path traversal, and hostile archive metadata. Add CI for the companion separately from the original engine.

## Security boundaries

- Never execute an artifact just because it was opened.
- Never accept arbitrary shell commands from the UI or an AI response.
- Treat decompiler output and extracted strings as untrusted data; render as text, not HTML.
- Keep local service endpoints loopback-only and require a session token.
- Preserve provenance: distinguish observed facts from heuristics and AI-generated interpretations.
