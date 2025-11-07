"""Bundled configuration assets for XCIP Master."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

__all__ = ["iter_configs", "default_config_file"]

_PACKAGE_DIR = Path(__file__).resolve().parent


def iter_configs() -> Iterator[Path]:
    """Yield paths to bundled CIP configuration files."""
    for entry in _PACKAGE_DIR.glob("*.xml"):
        yield entry


def default_config_file() -> Path:
    """Return the path to the bundled default CIP configuration file."""
    return _PACKAGE_DIR / "cip_xml_config.xml"
