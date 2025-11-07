"""Shared pytest configuration for the test suite."""
from __future__ import annotations

import sys
from pathlib import Path

from ._stubs import install_comm_stub, install_common_stubs

install_common_stubs()
install_comm_stub()

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
