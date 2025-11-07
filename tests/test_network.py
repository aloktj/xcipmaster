import logging
import subprocess
from typing import List

from xcipmaster.network import NetworkCommandRunner, NetworkTestService


class FakeRunner(NetworkCommandRunner):
    def __init__(self, *, ping_status=0, route_output="", route_error=None):
        self.ping_status = ping_status
        self.route_output = route_output
        self.route_error = route_error
        self.ping_calls = []
        self.route_calls = []

    def ping(self, ip_address: str) -> int:  # type: ignore[override]
        self.ping_calls.append(ip_address)
        return self.ping_status

    def route(self, command: List[str]):  # type: ignore[override]
        self.route_calls.append(command)
        if self.route_error:
            raise self.route_error
        return subprocess.CompletedProcess(command, 0, stdout=self.route_output, stderr="")


def make_service(runner):
    return NetworkTestService(logger=logging.getLogger("test"), runner=runner)


def test_communicate_with_target_success():
    runner = FakeRunner(ping_status=0)
    service = make_service(runner)
    service.ip_address = "192.0.2.1"

    assert service.communicate_with_target() is True
    assert service.net_test_flag is True
    assert runner.ping_calls == ["192.0.2.1"]


def test_communicate_with_target_failure():
    runner = FakeRunner(ping_status=1)
    service = make_service(runner)
    service.ip_address = "192.0.2.1"

    assert service.communicate_with_target() is False
    assert service.net_test_flag is False
    assert runner.ping_calls == ["192.0.2.1"]


def test_get_multicast_route_linux(monkeypatch):
    output = "default via 10.0.0.1 dev eth0\n224.0.0.0/4 dev eth0"
    runner = FakeRunner(route_output=output)
    service = make_service(runner)

    monkeypatch.setattr("xcipmaster.network.platform.system", lambda: "Linux")

    assert service.get_multicast_route() == "224.0.0.0/4"
    assert service.multicast_route_exist is True
    assert runner.route_calls == [["ip", "route"]]


def test_get_multicast_route_handles_errors(monkeypatch):
    error = subprocess.CalledProcessError(returncode=1, cmd=["ip", "route"])
    runner = FakeRunner(route_error=error)
    service = make_service(runner)

    monkeypatch.setattr("xcipmaster.network.platform.system", lambda: "Linux")

    assert service.get_multicast_route() is None
    assert service.multicast_route_exist is False
    assert runner.route_calls == [["ip", "route"]]


def test_check_multicast_support_matches_route(monkeypatch):
    output = "default via 10.0.0.1 dev eth0\n224.0.0.0/4 dev eth0"
    runner = FakeRunner(route_output=output)
    service = make_service(runner)
    service.user_multicast_address = "239.1.2.3"

    monkeypatch.setattr("xcipmaster.network.platform.system", lambda: "Linux")

    assert service.check_multicast_support() is True
    assert service.multicast_test_status is True

