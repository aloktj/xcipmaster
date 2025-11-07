import sys
from pathlib import Path
import threading

import click
import pytest
from click.testing import CliRunner

from tests._stubs import install_comm_stub, install_common_stubs

install_common_stubs()
install_comm_stub()

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

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
        self.packet_instances = {}

    def load_configuration(self, config_path: str) -> CIPConfigResult:
        self.load_calls.append(Path(config_path))
        return CIPConfigResult(
            resolved_path=Path("fake.xml"),
            tests=self._latest_results.copy(),
            success=True,
        )

    def latest_results(self):
        return list(self._latest_results)

    def get_packet_instance(self, subtype: str):
        return self.packet_instances.get(subtype)

    def set_packet_instance(self, subtype: str, packet):
        self.packet_instances[subtype] = packet

    def get_field_metadata(self, subtype: str):
        return []


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
