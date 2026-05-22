from __future__ import annotations

import hashlib
from pathlib import Path

from context_sast.models import LoadedApk


class ApkLoader:
    def load(self, apk_path: str | Path) -> LoadedApk:
        path = Path(apk_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"APK not found: {path}")
        if path.suffix.lower() != ".apk":
            raise ValueError(f"Expected an .apk file, got: {path.name}")

        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)

        return LoadedApk(path=path, sha256=digest.hexdigest(), size_bytes=path.stat().st_size)
