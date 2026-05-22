# Context-Aware Android SAST Engine

## What It Does

- Loads and fingerprints APK files.
- Parses the Android manifest to model exported attack surface.
- Uses Androguard to inspect Dalvik bytecode.
- Runs a bounded inter-procedural taint/data-flow pass from exposed entry points.
- Tracks flow-specific validations and lightweight field/array propagation to reduce false positives.
- Correlates manifest exposure with code-level flows.
- Executes modular detector plugins for:
  - Intent redirection
  - WebView misconfiguration
  - Insecure content providers
  - Browsable deep link abuse
- Produces CLI summaries, JSON output, and a local upload-and-scan dashboard.

## CLI Usage

Scan one APK with the human-readable summary:

```bash
python cli.py --apk test\com.motorola.securityhub.apk
```

Write JSON output in the original fast format:

```bash
python cli.py --apk-dir test --output scan-results.json
```

Print JSON to stdout:

```bash
python cli.py --apk test\com.motorola.securityhub.apk --json-only
```

Include nearby Java/XML evidence snippets in JSON output:

```bash
python cli.py --apk test\com.motorola.securityhub.apk --output securityhub-scan.json --show-near-code
```

`--show-near-code` is intentionally opt-in. It resolves source snippets around the relevant sink and manifest declaration, so it is slower than the default JSON output.

## Dashboard

Run the upload-and-scan dashboard:

```bash
python dashboard_server.py
```

Then open `http://127.0.0.1:8000/dashboard/`, upload an APK, and review the findings in the web UI. The dashboard always resolves nearby evidence snippets because it is designed for demo presentation rather than fast raw JSON export.

When a dashboard upload starts, the server now prints:

```text
[dashboard] received upload: <apk>
[dashboard] completed scan: <apk>
```

Jadx is required for --show-near-code flag

## Notes

- The current engine is intentionally modular and detector-oriented.
- The data-flow pass is bounded, but it carries flow-specific validation evidence instead of treating validation as a method-wide boolean.
- Detector confidence and suppression logic consider sink-specific validations and common false-positive cases such as non-exported grant-only providers.
- The dashboard under `dashboard/` is standalone and does not alter the engine or detector pipeline.
- `dashboard_server.py` is a thin local wrapper that serves the UI and calls the existing scan engine on uploaded APKs.
