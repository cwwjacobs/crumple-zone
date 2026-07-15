"""Small stdlib-only PEP 517 backend for the pinned Build Target 1 package."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import tarfile
import zipfile
from pathlib import Path


NAME = "crumple_zone"
VERSION = "0.1.0"
DIST_INFO = f"{NAME}-{VERSION}.dist-info"


def get_requires_for_build_wheel(_config_settings=None):
    return []


def get_requires_for_build_sdist(_config_settings=None):
    return []


def prepare_metadata_for_build_wheel(metadata_directory, _config_settings=None):
    destination = Path(metadata_directory) / DIST_INFO
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in _metadata_files().items():
        (destination / name).write_bytes(data)
    return DIST_INFO


def build_wheel(wheel_directory, _config_settings=None, _metadata_directory=None):
    root = Path.cwd()
    filename = f"{NAME}-{VERSION}-py3-none-any.whl"
    destination = Path(wheel_directory) / filename
    files: dict[str, bytes] = {}
    for path in sorted((root / "src/crumple_zone").glob("*.py")):
        files[f"crumple_zone/{path.name}"] = path.read_bytes()
    for name, data in _metadata_files().items():
        files[f"{DIST_INFO}/{name}"] = data
    record_path = f"{DIST_INFO}/RECORD"
    record = io.StringIO()
    writer = csv.writer(record, lineterminator="\n")
    for path, data in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow([path, f"sha256={digest}", len(data)])
    writer.writerow([record_path, "", ""])
    files[record_path] = record.getvalue().encode()
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as wheel:
        for path, data in files.items():
            info = zipfile.ZipInfo(path, (2026, 7, 15, 5, 0, 0))
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            wheel.writestr(info, data)
    return filename


def build_sdist(sdist_directory, _config_settings=None):
    root = Path.cwd()
    filename = f"crumple_zone-{VERSION}.tar.gz"
    destination = Path(sdist_directory) / filename
    admitted = [root / "pyproject.toml", *sorted((root / "src/crumple_zone").glob("*.py"))]
    with tarfile.open(destination, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        for path in admitted:
            archive.add(path, arcname=f"crumple_zone-{VERSION}/{path.relative_to(root)}", recursive=False)
    return filename


def _metadata_files() -> dict[str, bytes]:
    return {
        "METADATA": (
            "Metadata-Version: 2.4\nName: crumple-zone\nVersion: 0.1.0\n"
            "Summary: Host-enforced evidence chamber for bounded tool-using agent exercises\n"
            "Requires-Python: >=3.14\n\n"
        ).encode(),
        "WHEEL": b"Wheel-Version: 1.0\nGenerator: crumple-stdlib-backend.v1\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        "entry_points.txt": b"[console_scripts]\ncrumple = crumple_zone.cli:main\n",
    }
