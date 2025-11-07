"""Test support utilities for stubbing third-party dependencies."""
from __future__ import annotations

import sys
import threading
import types
from typing import Optional


class _DummyPacket:
    def __init__(self, *args, **kwargs):
        pass

    def __len__(self):
        return 0


class _DummyField:
    def __init__(self, *args, **kwargs):
        self.name = kwargs.get("name")
        if not self.name and args:
            self.name = args[0]


class _DummyFloatField(_DummyField):
    pass


class _DummyStrField(_DummyField):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        length = 0
        if args:
            last = args[-1]
            if isinstance(last, int):
                length = last
        length = kwargs.get("length", length)
        self._length = length

    def length_from(self, packet):
        return self._length


scapy_all_stub = types.SimpleNamespace(
    Packet=_DummyPacket,
    ByteField=_DummyField,
    BitField=_DummyField,
    IEEEFloatField=_DummyFloatField,
    StrFixedLenField=_DummyStrField,
    LEIntField=_DummyField,
    ShortField=_DummyField,
    SignedByteField=_DummyField,
    LEShortField=_DummyField,
    IEEEDoubleField=_DummyField,
)


def install_common_stubs() -> None:
    """Install light-weight stand-ins for optional third-party packages."""

    scapy_stub = types.ModuleType("scapy")
    scapy_stub.all = scapy_all_stub
    sys.modules["scapy"] = scapy_stub

    pyfiglet_stub = types.ModuleType("pyfiglet")
    pyfiglet_stub.figlet_format = lambda text, font=None: text
    sys.modules.setdefault("pyfiglet", pyfiglet_stub)

    termcolor_stub = types.ModuleType("termcolor")
    termcolor_stub.colored = lambda text, color=None: text
    sys.modules.setdefault("termcolor", termcolor_stub)

    tabulate_stub = types.ModuleType("tabulate")
    tabulate_stub.tabulate = lambda data, headers=None, tablefmt=None, colalign=None: "\n".join(
        ["\t".join(map(str, row)) for row in data]
    )
    sys.modules.setdefault("tabulate", tabulate_stub)


class _StubCommunicationManager:
    def __init__(self, *args, **kwargs):
        self.lock = threading.Lock()
        self.enable_auto_reconnect = False
        self.start_comm_thread_instance: Optional[threading.Thread] = None

    def start(self):
        pass

    def stop(self):
        pass


def install_comm_stub():
    """Provide a stub ``xcipmaster.comm`` module for CLI tests."""

    comm_stub = types.ModuleType("xcipmaster.comm")
    comm_stub.CommunicationManager = _StubCommunicationManager
    comm_stub.default_client_factory = lambda **kwargs: None
    comm_stub.default_thread_factory = lambda **kwargs: None
    sys.modules.setdefault("xcipmaster.comm", comm_stub)
    return comm_stub


__all__ = [
    "install_common_stubs",
    "install_comm_stub",
    "scapy_all_stub",
    "_DummyPacket",
    "_DummyField",
    "_DummyFloatField",
    "_DummyStrField",
]
