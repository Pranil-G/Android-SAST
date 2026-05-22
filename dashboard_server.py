from __future__ import annotations

import argparse
import json
import tempfile
from email.parser import BytesParser
from email.policy import default
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from context_sast.engine import ContextAwareSASTEngine
from context_sast.reports.formatter import result_to_dict

ROOT_DIR = Path(__file__).resolve().parent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local dashboard server for the Android SAST engine")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=8000, help="Bind port")
    parser.add_argument("--max-depth", type=int, default=4, help="Maximum inter-procedural depth for scans")
    return parser


class DashboardHandler(SimpleHTTPRequestHandler):
    server_version = "ContextSASTDashboard/0.1"

    def __init__(self, *args, max_depth: int = 4, **kwargs) -> None:
        self.max_depth = max_depth
        super().__init__(*args, directory=str(ROOT_DIR), **kwargs)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "/dashboard/")
            self.end_headers()
            return
        if parsed.path == "/api/health":
            self._send_json({"status": "ok"})
            return
        super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/api/scan":
            self.send_error(HTTPStatus.NOT_FOUND, "Unknown API route")
            return

        try:
            form = self._parse_multipart()
            upload = form.get("apk")
            if not upload or not upload["data"]:
                self._send_json({"error": "Missing uploaded APK field named 'apk'."}, status=HTTPStatus.BAD_REQUEST)
                return
            filename = upload["filename"] or "uploaded.apk"
            print(f"[dashboard] received upload: {filename}", flush=True)
            max_depth_raw = form.get("max_depth", {}).get("text")
            max_depth = self.max_depth
            if max_depth_raw:
                try:
                    max_depth = max(1, int(max_depth_raw))
                except ValueError:
                    pass

            payload = self._scan_upload(filename, upload["data"], max_depth)
            print(f"[dashboard] completed scan: {filename}", flush=True)
            self._send_json(payload)
        except ValueError as error:
            self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
        except Exception as error:  # pragma: no cover - defensive server path
            self._send_json({"error": f"Scan failed: {error}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _parse_multipart(self) -> dict[str, dict[str, object]]:
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            raise ValueError("Expected multipart/form-data upload.")

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if not body:
            raise ValueError("Empty request body.")

        raw_message = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + body
        message = BytesParser(policy=default).parsebytes(raw_message)
        if not message.is_multipart():
            raise ValueError("Malformed multipart request.")

        fields: dict[str, dict[str, object]] = {}
        for part in message.iter_parts():
            name = part.get_param("name", header="content-disposition")
            if not name:
                continue
            payload = part.get_payload(decode=True) or b""
            filename = part.get_filename()
            fields[name] = {
                "filename": filename,
                "data": payload,
                "text": payload.decode("utf-8", errors="replace").strip(),
            }
        return fields

    def _scan_upload(self, filename: str, content: bytes, max_depth: int) -> dict[str, object]:
        suffix = Path(filename).suffix or ".apk"
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(prefix="context-sast-", suffix=suffix, delete=False) as temp_file:
                temp_file.write(content)
                temp_path = Path(temp_file.name)

            result = ContextAwareSASTEngine(max_depth=max_depth).scan(str(temp_path))
            return {
                "results": [
                    result_to_dict(result, include_evidence=True, apk_path_override=filename)
                ]
            }
        finally:
            if temp_path and temp_path.exists():
                temp_path.unlink()

    def _send_json(self, payload: dict[str, object], status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    def handler(*handler_args, **handler_kwargs):
        return DashboardHandler(*handler_args, max_depth=args.max_depth, **handler_kwargs)

    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"Dashboard running at http://{args.host}:{args.port}/dashboard/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
