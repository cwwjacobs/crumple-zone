"""Validated production install layout with private source-tree test injection."""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path


class ResourceError(RuntimeError):
    pass


@dataclass(frozen=True)
class InstallLayout:
    resource_root: Path
    state_root: Path
    source_root: Path | None


def production_layout() -> InstallLayout:
    package = Path(__file__).resolve().parent
    source = package.parents[1]
    if _is_source_root(source):
        return _validated_layout(source, source / ".crumple", source)
    state = Path(sys.prefix).resolve().parent
    resources = state / "resources"
    _verify_install_manifest(resources)
    return _validated_layout(resources, state, None)


def _layout_for_tests(root: Path) -> InstallLayout:
    resolved = root.resolve()
    resource_root = resolved if _has_required_resources(resolved) else production_layout().resource_root
    return _validated_layout(resource_root, resolved / ".crumple", resolved if (resolved / ".git").exists() else None)


def _validated_layout(resource_root: Path, state_root: Path, source_root: Path | None) -> InstallLayout:
    root = resource_root.resolve()
    state = state_root.resolve()
    required = (
        root / "contracts/event.schema.json",
        root / "contracts/evidence_envelope.schema.json",
        root / "scenarios/poisoned-tool-surface-v1.json",
        root / "scenarios/poisoned-tool-surface-v1.tools.json",
        root / "locks/poisoned-tool-surface-v1.json",
        root / "locks/phase3-guest-image.json",
    )
    if any(not path.is_file() for path in required):
        raise ResourceError("INSTALL_RESOURCE_ROOT_INVALID")
    return InstallLayout(root, state, source_root.resolve() if source_root is not None else None)


def _has_required_resources(root: Path) -> bool:
    return (root / "contracts/event.schema.json").is_file() and (root / "scenarios/poisoned-tool-surface-v1.json").is_file()


def _is_source_root(root: Path) -> bool:
    pyproject = root / "pyproject.toml"
    return pyproject.is_file() and 'name = "crumple-zone"' in pyproject.read_text(encoding="utf-8")


def _verify_install_manifest(root: Path) -> None:
    manifest_path = root / "install-manifest.json"
    if not manifest_path.is_file():
        raise ResourceError("INSTALL_MANIFEST_MISSING")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ResourceError("INSTALL_MANIFEST_INVALID") from exc
    if set(manifest) != {"schema_version", "files"} or manifest["schema_version"] != "install-manifest.v1":
        raise ResourceError("INSTALL_MANIFEST_INVALID")
    files = manifest["files"]
    if not isinstance(files, list) or not files:
        raise ResourceError("INSTALL_MANIFEST_INVALID")
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ResourceError("INSTALL_MANIFEST_INVALID")
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ResourceError("INSTALL_MANIFEST_PATH_INVALID")
        candidate = root / relative
        if not candidate.is_file() or _sha256(candidate) != item["sha256"]:
            raise ResourceError("INSTALL_RESOURCE_HASH_MISMATCH")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
