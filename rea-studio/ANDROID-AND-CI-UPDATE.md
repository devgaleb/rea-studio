# Advanced workbench follow-up

## Control-flow canvas

The function evidence panel now draws exported basic blocks and successor edges as an interactive SVG graph. Blocks are keyboard-focusable/clickable and link to the corresponding block list. The graph deliberately shows only edges exported by the provider; it does not infer missing edges. Current layout is a compact grid rather than a force-directed or hierarchical layout.

## Android source cross-references

`local-service/android_analysis.py` reports decoded manifest permissions/components, a curated set of sensitive permission labels, source method declarations, lexical call-site candidates, same-name candidate matches, and selected security-relevant string indicators. Every source candidate includes a JADX output path and line. It is intentionally not called a complete call graph: overloaded methods, Kotlin, reflection, native methods, obfuscation, and dynamic dispatch need deeper parsing/resolution.

## Tests

`python -m unittest discover -s rea-studio/local-service/tests -v` exercises provider-shaped Ghidra/IDA exports and a JADX manifest/source fixture. Optional integration checks accept actual output paths via `REA_GHIDRA_TEST_JSON`, `REA_IDA_TEST_JSON`, and `REA_JADX_TEST_DIR`; those skip unless configured. This environment does not have Ghidra, IDA, JADX or Windows, so those live-provider and installer tests could not be executed here.

## Windows build

The root `.github/workflows/windows-installer.yml` pins the runner family and direct tool versions, builds a PyInstaller bridge and NSIS installer, then emits SHA-256 plus a build manifest. This workspace has no npm registry access, so it could not generate the transitive `package-lock.json`. The workflow bootstraps one when missing and uploads it; for fully repeatable releases, commit that generated lockfile after the first successful CI run. The current deliverable therefore contains a reproducible build recipe, but not a locally built Windows installer nor a committed npm lockfile.
