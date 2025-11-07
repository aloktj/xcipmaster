import logging
import sys
import types
from types import SimpleNamespace

class _StubField:
    def __init__(self, *args, **kwargs):
        pass


class _StubPacket:
    def __init__(self, *args, **kwargs):
        pass


class _StubFloatField(_StubField):
    pass


class _StubStrField(_StubField):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        length = 0
        if args:
            last = args[-1]
            if isinstance(last, int):
                length = last
        length = kwargs.get("length", length)
        self._length = length

    def length_from(self, _packet):  # pragma: no cover - compatibility shim
        return self._length


class _StubByteField(_StubField):
    pass


scapy_all_stub = types.SimpleNamespace(
    Packet=_StubPacket,
    ByteField=_StubByteField,
    BitField=_StubField,
    IEEEFloatField=_StubFloatField,
    StrFixedLenField=_StubStrField,
    LEIntField=_StubField,
    ShortField=_StubField,
    SignedByteField=_StubField,
    LEShortField=_StubField,
    IEEEDoubleField=_StubField,
)
scapy_stub = types.ModuleType("scapy")
scapy_stub.all = scapy_all_stub
sys.modules.setdefault("scapy", scapy_stub)

# Provide lightweight stubs for the third-party CIP client implementation so
# importing :mod:`xcipmaster.comm` does not pull heavy dependencies during the
# unit tests.
tgv_stub = types.ModuleType("thirdparty.scapy_cip_enip.tgv2020")


class _StubClient:
    def __init__(self, *args, **kwargs):
        self.connected = False

    def forward_open(self):  # pragma: no cover - defensive stub
        return False

    def forward_close(self):  # pragma: no cover - defensive stub
        return None

    def close(self):  # pragma: no cover - defensive stub
        return None


tgv_stub.Client = _StubClient

thirdparty_module = sys.modules.setdefault("thirdparty", types.ModuleType("thirdparty"))
thirdparty_module.__path__ = []  # mark as package

scapy_cip_enip_module = sys.modules.setdefault(
    "thirdparty.scapy_cip_enip", types.ModuleType("thirdparty.scapy_cip_enip")
)
scapy_cip_enip_module.__path__ = []  # mark as package
scapy_cip_enip_module.tgv2020 = tgv_stub

sys.modules.setdefault("thirdparty.scapy_cip_enip.tgv2020", tgv_stub)

# Ensure we load the real communication module rather than the CLI test stub.
sys.modules.pop("xcipmaster.comm", None)

from xcipmaster.comm import CommunicationManager


class FakeAssembly:
    def __init__(self, size: int):
        self.attrib = {"size": str(size)}


class FakeConfigService:
    def __init__(self):
        self.logger = logging.getLogger("FakeConfigService")
        self.ot_eo_assemblies = FakeAssembly(16)
        self.to_assemblies = FakeAssembly(16)
        self.OT_packet_class = self._make_ot_packet_class()
        self.TO_packet_class = self._make_to_packet_class()
        self.OT_packet = self.OT_packet_class()
        self.TO_packet = None

    @staticmethod
    def _make_ot_packet_class():
        class _FakeOTPacket:
            MPU_CTCMSAlive = scapy_all_stub.ByteField("MPU_CTCMSAlive", 0)

            def __init__(self):
                self.MPU_CTCMSAlive = 0
                self.MPU_CDateTimeSec = 0

        return _FakeOTPacket

    @staticmethod
    def _make_to_packet_class():
        class _FakeTOPacket:
            def __init__(self, payload):
                self.payload = payload

        return _FakeTOPacket


class FakeNetworkService:
    ip_address = "192.0.2.1"
    user_multicast_address = "239.255.0.1"


class FakeClient:
    def __init__(self):
        self.connected = True
        self.forward_open_called = 0
        self.forward_close_called = 0
        self.closed = 0
        self.recv_calls = 0
        self.send_calls = []

    def forward_open(self):
        self.forward_open_called += 1
        return True

    def forward_close(self):
        self.forward_close_called += 1

    def close(self):
        self.closed += 1

    def recv_UDP_ENIP_CIP_IO(self, *_args, **_kwargs):
        self.recv_calls += 1
        if self.recv_calls == 1:
            return SimpleNamespace(payload=SimpleNamespace(load=b"payload"))
        return None

    def send_UDP_ENIP_CIP_IO(self, **kwargs):
        self.send_calls.append(kwargs)


def test_run_once_uses_fake_client_and_stays_synchronous():
    config = FakeConfigService()
    network = FakeNetworkService()
    created_clients = []

    def fake_client_factory(**kwargs):
        client = FakeClient()
        client.factory_kwargs = kwargs
        created_clients.append(client)
        return client

    def forbidden_thread_factory(*_args, **_kwargs):
        raise AssertionError("Thread factory should not be used for run_once")

    manager = CommunicationManager(
        config,
        network,
        logger=logging.getLogger("test"),
        client_factory=fake_client_factory,
        thread_factory=forbidden_thread_factory,
    )

    result = manager.run_once()

    assert result is True
    assert len(created_clients) == 1
    client = created_clients[0]
    assert client.factory_kwargs["ip_address"] == network.ip_address
    assert client.factory_kwargs["multicast_address"] == network.user_multicast_address
    assert client.forward_open_called == 1
    assert client.send_calls, "IO payload should be transmitted"
    assert client.forward_close_called == 0
    assert client.closed == 1
    assert manager.bCIPErrorOccured is True


class FakeThread:
    def __init__(self, *, target, name=None):
        self._target = target
        self.name = name
        self._alive = False
        self.started = False

    def start(self):
        self.started = True
        self._alive = True
        try:
            self._target()
        finally:
            self._alive = False

    def is_alive(self):
        return self._alive

    def join(self, timeout=None):  # pragma: no cover - compatibility shim
        return None


def test_start_uses_injected_thread_factory():
    config = FakeConfigService()
    network = FakeNetworkService()
    clients = []

    def fake_client_factory(**_kwargs):
        client = FakeClient()
        clients.append(client)
        return client

    threads = []

    def fake_thread_factory(**kwargs):
        thread = FakeThread(**kwargs)
        threads.append(thread)
        return thread

    manager = CommunicationManager(
        config,
        network,
        logger=logging.getLogger("test"),
        client_factory=fake_client_factory,
        thread_factory=fake_thread_factory,
    )

    manager.start()

    assert threads, "Thread factory should be invoked"
    thread = threads[0]
    assert thread.started is True
    assert not thread.is_alive()
    assert clients, "Client factory should create a client"
    client = clients[0]
    assert client.forward_open_called == 1
    assert client.closed == 1

