from __future__ import annotations

import json
import os
import shutil
from pathlib import Path


class StorageError(RuntimeError):
    pass


def load_baseline(output_dir: Path) -> dict | None:
    path = output_dir / "rule_baseline.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StorageError(f"Invalid existing baseline: {exc}") from exc


def publish(staging: Path, output_dir: Path, allow_unmanaged: bool = False) -> None:
    manifest = json.loads((staging / "manifest.json").read_text(encoding="utf-8"))
    managed = set(manifest["managed_files"])
    if output_dir.exists():
        existing = {path.name for path in output_dir.iterdir() if path.is_file()}
        existing_manifest = output_dir / "manifest.json"
        if existing and existing_manifest.exists():
            prior = json.loads(existing_manifest.read_text(encoding="utf-8"))
            allowed_existing = set(prior.get("managed_files", []))
            unknown = existing - allowed_existing
            if unknown:
                raise StorageError("dist contains unmanaged files: " + ", ".join(sorted(unknown)))
        elif existing and not allow_unmanaged:
            raise StorageError("dist exists without a managed manifest; initialize from a preview first")
    replacement = output_dir.with_name(output_dir.name + ".new")
    backup = output_dir.with_name(output_dir.name + ".previous")
    if replacement.exists():
        shutil.rmtree(replacement)
    shutil.copytree(staging, replacement)
    if backup.exists():
        shutil.rmtree(backup)
    if output_dir.exists():
        os.replace(output_dir, backup)
    os.replace(replacement, output_dir)
    if backup.exists():
        shutil.rmtree(backup)
