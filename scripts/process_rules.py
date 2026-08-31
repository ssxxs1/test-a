#!/usr/bin/env python3
"""Build auditable Stable and Lite proxy rule providers."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from rules.config import ConfigurationError, file_sha256, load_config
from rules.fetch import FetchError, fetch_source
from rules.guards import GuardError, verify_baseline
from rules.parse import consolidate_source_records, parse_source
from rules.pipeline import build_profiles
from rules.reporting import write_outputs
from rules.storage import StorageError, load_baseline, publish

PROCESSOR_VERSION = 3


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def dependency_identity(root: Path) -> str:
    return file_sha256(root / "requirements.txt")


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output_dir", default="dist")
    parser.add_argument("--preview-only", action="store_true", help="Build a candidate without publishing it")
    parser.add_argument("--initialize-baseline", action="store_true", help="Replace the approved baseline after review")
    parser.add_argument("--approve-anomalous-publish", action="store_true")
    parser.add_argument("--approval-reason")
    parser.add_argument("--preview-manifest", type=Path, help="Reviewed preview manifest that must match this build")
    parser.add_argument("--publish-candidate", action="store_true", help="Apply production baseline checks while producing an artifact")
    parser.add_argument("--force", action="store_true", help="Rebuild even when input identity is unchanged")
    return parser.parse_args(argv)


def _read_preview_identity(path: Path) -> dict:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    return manifest["identity"]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.approve_anomalous_publish and not args.approval_reason:
        raise SystemExit("--approval-reason is required with --approve-anomalous-publish")
    if args.initialize_baseline and not args.preview_only:
        raise SystemExit("--initialize-baseline only creates a reviewed preview candidate; publishing is handled by the workflow")
    if args.publish_candidate and not args.preview_only:
        raise SystemExit("--publish-candidate must be used with --preview-only")
    root = repo_root()
    requested_output = (root / args.output_dir).resolve() if not Path(args.output_dir).is_absolute() else Path(args.output_dir).resolve()
    if requested_output.parent != root.resolve():
        raise SystemExit("output_dir must be a direct child of the repository root")
    try:
        config = load_config(root)
        with ThreadPoolExecutor(max_workers=len(config.sources)) as executor:
            content_by_source = dict(zip(config.sources, executor.map(fetch_source, config.sources)))
        results = [parse_source(source, content_by_source[source], config.policy) for source in config.sources]
        for result in results:
            if result.parsed_rules > result.source.max_rules:
                raise FetchError(f"{result.source.source_id}: parsed rule count exceeds max_rules")
            result.records = consolidate_source_records(result.records)
            result.parsed_rules = sum(1 for record in result.records if record.rule)
        identity = {
            "policy_version": config.policy["policy_version"], "policy_hash": config.policy_hash,
            "sources_version": json.loads((root / "scripts" / "sources.json").read_text(encoding="utf-8"))["sources_version"], "sources_hash": config.sources_hash,
            "processor_version": PROCESSOR_VERSION, "processor_hash": file_sha256(Path(__file__)),
            "dependency_identity": dependency_identity(root),
            "source_canonical_hashes": {result.source.source_id: result.canonical_events_hash for result in results},
            "source_raw_hashes": {result.source.source_id: result.raw_content_hash for result in results},
        }
        baseline = load_baseline(requested_output)
        if args.preview_manifest:
            if _read_preview_identity(args.preview_manifest) != identity:
                raise GuardError("Current complete build identity differs from the reviewed preview")
        if baseline and baseline.get("identity") == identity and not args.force and not args.preview_only and not args.initialize_baseline:
            print("Skipping: all build inputs match the published baseline.")
            return 0
        profiles, _ = build_profiles(results, config.policy)
        approval = {"reason": args.approval_reason} if args.approve_anomalous_publish else None
        stage_parent = Path(tempfile.mkdtemp(prefix="rules-build-", dir=root))
        staging = stage_parent / "dist"
        try:
            current = write_outputs(staging, profiles, results, config.policy, identity, baseline, approval)
            warnings = []
            if args.publish_candidate:
                warnings = verify_baseline(current, baseline, config.policy, args.approve_anomalous_publish, args.initialize_baseline)
            if warnings:
                print("Approved guard warnings: " + "; ".join(warnings), file=sys.stderr)
            if args.preview_only:
                target = root / "preview-dist"
                if target.exists():
                    shutil.rmtree(target)
                shutil.copytree(staging, target)
                print(f"Preview saved to {target}")
                return 0
            publish(staging, requested_output, allow_unmanaged=args.initialize_baseline)
            print(f"Published {requested_output}")
            return 0
        finally:
            shutil.rmtree(stage_parent, ignore_errors=True)
    except (ConfigurationError, FetchError, GuardError, StorageError, OSError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
