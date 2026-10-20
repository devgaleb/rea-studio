# Windows desktop build

The NSIS installer build is automated by `.github/workflows/windows-installer.yml` on `windows-2022`. It pins Node `22.14.0`, Python `3.12.8`, Electron `36.9.5`, electron-builder `26.0.12`, and PyInstaller `6.13.0`; the workflow creates a one-file `rea-bridge.exe`, builds the x64 installer, emits `SHA256SUMS.txt` plus a build manifest, and uploads the installer and dependency lockfile as a CI artifact.

## Local build on Windows

1. Install Node.js 22.14.0 and Python 3.12.8.
2. From this directory run `npm install --package-lock-only --ignore-scripts` once and commit `package-lock.json` to pin transitive npm dependencies.
3. Run `npm ci`.
4. Run `build-bridge-windows.bat` (PyInstaller is pinned by that script).
5. Run `npm run dist:win`.
6. Hash the generated installer with `Get-FileHash .\dist\REA-Studio-*-Windows-x64.exe -Algorithm SHA256`.

For a fully repeatable release, commit the generated `package-lock.json` and build from the same source commit/toolchain. The workflow bootstraps a missing lockfile for first-run convenience; that bootstrap is not as reproducible as a committed lockfile. CI artifacts include the exact lockfile and its SHA-256 in `build-manifest.json`.

The installer bundles the Python bridge, but Ghidra, JADX, and a licensed IDA installation are external analysis dependencies and are not redistributed. A signed installer requires the publisher's signing certificate and secrets; CI currently produces an unsigned installer. Run optional real-provider tests by setting `REA_GHIDRA_TEST_JSON`, `REA_IDA_TEST_JSON`, and/or `REA_JADX_TEST_DIR` before running `python -m unittest discover -s ../local-service/tests -v`.
