"""Helpers for locating package data and resources."""

from __future__ import annotations

from pathlib import Path


def package_root() -> Path:
    """Return the root directory of the installed :mod:`xcipmaster` package."""
    return Path(__file__).resolve().parent


def default_config_directory() -> Path:
    """Return the directory containing the bundled CIP configuration files."""
    return package_root() / "conf"


def default_config_file() -> Path:
    """Return the bundled default CIP configuration file."""
    return default_config_directory() / "cip_xml_config.xml"
