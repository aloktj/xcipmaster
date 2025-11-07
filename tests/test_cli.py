import sys
import types
from pathlib import Path
import threading

import click
import pytest
from click.testing import CliRunner


class _DummyPacket:
    def __init__(self, *args, **kwargs):
        pass

    def __len__(self):
        return 0


class _DummyField:
    def __init__(self, *args, **kwargs):
        pass


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

scapy_stub = types.ModuleType("scapy")
scapy_stub.all = scapy_all_stub
sys.modules.setdefault("scapy", scapy_stub)

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

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

comm_stub = types.ModuleType("xcipmaster.comm")


class _StubCommunicationManager:
    def __init__(self, *args, **kwargs):
        self.lock = threading.Lock()
        self.enable_auto_reconnect = False
        self.start_comm_thread_instance = None

    def start(self):
        pass

    def stop(self):
        pass


comm_stub.CommunicationManager = _StubCommunicationManager
comm_stub.default_client_factory = lambda **kwargs: None
comm_stub.default_thread_factory = lambda **kwargs: None
sys.modules.setdefault("xcipmaster.comm", comm_stub)

import xcipmaster.cli.commands as cli_commands
import xcipmaster.cli.controller as cli_controller
from xcipmaster.cli.commands import _initialize_controller, cli
from xcipmaster.cli.controller import CLI
from xcipmaster.config import CIPConfigResult
from xcipmaster.network import NetworkTestResult


class FakeConfigService:
    def __init__(self):
        self.load_calls = []
        self._latest_results = [("Fake CIP Test", "OK")]

    def load_configuration(self, config_path: str) -> CIPConfigResult:
        self.load_calls.append(Path(config_path))
        return CIPConfigResult(
            resolved_path=Path("fake.xml"),
            tests=self._latest_results.copy(),
            success=True,
        )

    def latest_results(self):
        return list(self._latest_results)


class FakeNetworkService:
    def __init__(self):
        self.configure_calls = []
        self.result = NetworkTestResult(
            target_ip="10.0.1.1",
            multicast_ip="239.192.1.3",
            tests=[("Fake Network Test", "OK")],
            success=True,
        )

    def configure(self, target_ip: str, multicast_ip: str) -> NetworkTestResult:
        self.configure_calls.append((target_ip, multicast_ip))
        return self.result


class FakeCommManager:
    def __init__(self):
        self.enable_auto_reconnect = False
        self.lock = threading.Lock()
        self.started = False
        self.stopped = False
        self._thread = None

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    @property
    def start_comm_thread_instance(self):
        return self._thread


def test_initialize_controller_skips_interactive_side_effects(monkeypatch):
    def fail_confirm(*args, **kwargs):  # pragma: no cover - defensive
        pytest.fail("click.confirm should not be called in test mode")

    monkeypatch.setattr(cli_commands.click, "confirm", fail_confirm)

    def factory() -> CLI:
        controller = CLI(
            config_service=FakeConfigService(),
            network_service=FakeNetworkService(),
            comm_manager=FakeCommManager(),
            test_mode=True,
        )

        controller.display_banner = lambda *a, **k: pytest.fail(
            "display_banner should be skipped"
        )
        controller.progress_bar = lambda *a, **k: pytest.fail(
            "progress_bar should be skipped"
        )
        controller.cip_config = lambda *a, **k: pytest.fail(
            "cip_config should not run in test mode"
        )
        controller.config_network = lambda *a, **k: pytest.fail(
            "config_network should not run in test mode"
        )
        return controller

    ctx = click.Context(cli, info_name="cli")
    ctx.resilient_parsing = False
    controller = _initialize_controller(ctx, factory)

    assert controller.test_mode is True


def test_start_command_uses_stubbed_services(monkeypatch):
    fake_config = FakeConfigService()
    fake_network = FakeNetworkService()
    fake_comm = FakeCommManager()

    controller = CLI(
        config_service=fake_config,
        network_service=fake_network,
        comm_manager=fake_comm,
        test_mode=True,
    )

    monkeypatch.setattr(cli_controller.time, "sleep", lambda *args, **kwargs: None)

    runner = CliRunner()
    result = runner.invoke(cli, ["start"], obj=controller)

    assert result.exit_code == 0
    assert fake_config.load_calls, "CIP configuration should be invoked"
    assert fake_network.configure_calls, "Network configuration should be invoked"
    assert fake_comm.started is True
