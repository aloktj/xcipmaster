import sys
import threading
import types
from pathlib import Path

import pytest

from tests._stubs import install_comm_stub, install_common_stubs

install_common_stubs()
install_comm_stub()

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from xcipmaster.cli.controller import CLI  # noqa: E402
from xcipmaster.config import CIPConfigService  # noqa: E402
from xcipmaster.paths import default_config_file  # noqa: E402


CONFIG_PATH = default_config_file()


class _StubCommManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.enable_auto_reconnect = False
        self.start_comm_thread_instance = None

    def start(self):
        pass

    def stop(self):
        pass


class _StubNetworkService:
    def configure(self, target_ip: str, multicast_ip: str):
        return types.SimpleNamespace(
            target_ip=target_ip,
            multicast_ip=multicast_ip,
            tests=[],
            success=True,
        )


@pytest.fixture(scope="module")
def config_service():
    service = CIPConfigService()
    result = service.load_configuration(str(CONFIG_PATH))
    assert result.success, "Fixture failed to load CIP configuration"
    return service


def test_service_exposes_packet_layouts(config_service):
    layouts = {layout.subtype: layout for layout in config_service.get_packet_layouts()}

    assert "OT_EO" in layouts
    assert "TO" in layouts

    ot_layout = config_service.get_packet_layout("OT_EO")
    assert ot_layout is not None
    assert config_service.get_packet_class("OT_EO") is ot_layout.packet_class

    ot_packet = config_service.get_packet_instance("OT_EO")
    assert ot_packet is not None
    assert isinstance(ot_packet, ot_layout.packet_class)

    fields = config_service.get_field_metadata("OT_EO")
    assert any(field["id"] == "MPU_CTCMSAlive" for field in fields)

    to_layout = config_service.get_packet_layout("TO")
    assert to_layout is not None
    assert config_service.get_packet_instance("TO") is not None


def test_cli_uses_service_packets(config_service, monkeypatch):
    monkeypatch.setattr(CLI, "display_banner", lambda *a, **k: None)
    monkeypatch.setattr(CLI, "progress_bar", lambda *a, **k: None)
    monkeypatch.setattr(CLI, "config_network", lambda *a, **k: True)

    controller = CLI(
        config_service=config_service,
        network_service=_StubNetworkService(),
        comm_manager=_StubCommManager(),
        test_mode=True,
    )

    assert controller.cip_config(str(CONFIG_PATH)) is True

    ot_layout = config_service.get_packet_layout("OT_EO")
    assert ot_layout is not None
    assert isinstance(controller.ot_packet, ot_layout.packet_class)

    to_layout = config_service.get_packet_layout("TO")
    assert to_layout is not None
    assert isinstance(controller.to_packet, to_layout.packet_class)

    ot_fields = config_service.get_field_metadata("OT_EO")
    assert ot_fields
