"""Network configuration and validation services."""
from __future__ import annotations

import ipaddress
import logging
import os
import platform
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


class NetworkCommandRunner:
    """Helper responsible for executing platform network commands."""

    def ping(self, ip_address: str) -> int:
        """Return the status code from invoking the platform ping command."""

        return os.system(f"ping -c 1 {ip_address}")

    def route(self, command: List[str]) -> subprocess.CompletedProcess[str]:
        """Execute a route inspection command and return the completed process."""

        return subprocess.run(
            command, capture_output=True, text=True, check=True
        )


@dataclass
class NetworkTestResult:
    """Result of executing network connectivity validation."""

    target_ip: Optional[str]
    multicast_ip: Optional[str]
    tests: List[Tuple[str, str]] = field(default_factory=list)
    success: bool = False


class NetworkTestService:
    """Service responsible for validating network reachability and multicast support."""

    def __init__(
        self,
        logger: Optional[logging.Logger] = None,
        runner: Optional[NetworkCommandRunner] = None,
    ):
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self._runner = runner or NetworkCommandRunner()
        self.ip_address: Optional[str] = None
        self.user_multicast_address: Optional[str] = None
        self.net_test_flag: bool = False
        self.multicast_test_status: bool = False
        self.multicast_route_exist: bool = False
        self.platform_multicast_route: Optional[str] = None

    def configure(self, target_ip: str, multicast_ip: str) -> NetworkTestResult:
        """Validate connectivity to *target_ip* and multicast compatibility."""

        self.logger.info("Validating network configuration")
        tests: List[Tuple[str, str]] = []

        self.net_test_flag = False
        self.multicast_test_status = False
        self.multicast_route_exist = False
        self.platform_multicast_route = None

        try:
            self.ip_address = str(ipaddress.IPv4Address(target_ip))
        except ipaddress.AddressValueError as exc:
            self.logger.error("Invalid target IP address: %s", exc)
            return NetworkTestResult(
                target_ip=None,
                multicast_ip=None,
                tests=[("Validate target IP", "FAILED")],
                success=False,
            )

        try:
            self.user_multicast_address = str(ipaddress.IPv4Address(multicast_ip))
        except ipaddress.AddressValueError as exc:
            self.logger.error("Invalid multicast IP address: %s", exc)
            return NetworkTestResult(
                target_ip=self.ip_address,
                multicast_ip=None,
                tests=[("Validate multicast IP", "FAILED")],
                success=False,
            )

        tests.append(("Communication with Target", "OK" if self.communicate_with_target() else "FAILED"))
        tests.append(("Mutlicast Group Join", "OK" if self.check_multicast_support() else "FAILED"))
        tests.append(("Mutlicast route Compatibity", "OK" if self.multicast_route_exist else "FAILED"))

        success = all(status == "OK" for _, status in tests)
        return NetworkTestResult(
            target_ip=self.ip_address,
            multicast_ip=self.user_multicast_address,
            tests=tests,
            success=success,
        )

    def get_multicast_route(self) -> Optional[str]:
        try:
            os_name = platform.system()
            if os_name == "Windows":
                result = self._runner.route(["route", "print"])
            elif os_name in ["Linux", "Darwin"]:
                result = self._runner.route(["ip", "route"])
            else:
                self.logger.warning("Unsupported operating system: %s", os_name)
                return None

            for line in result.stdout.splitlines():
                if "224.0.0.0/4" in line:
                    self.multicast_route_exist = True
                    return "224.0.0.0/4"
            return None
        except subprocess.CalledProcessError:
            self.logger.exception("Unable to execute route command")
            return None

    def check_multicast_support(self) -> bool:
        if not self.user_multicast_address:
            self.logger.error("No multicast address specified for validation")
            self.multicast_test_status = False
            return False

        try:
            user_ip = ipaddress.IPv4Address(self.user_multicast_address)
            self.platform_multicast_route = self.get_multicast_route()

            if self.multicast_route_exist and self.platform_multicast_route:
                platform_route = ipaddress.IPv4Network(self.platform_multicast_route)
                if user_ip in platform_route:
                    self.multicast_test_status = True
                    return True
                self.multicast_test_status = False
                return False

            self.multicast_test_status = False
            return False
        except ipaddress.AddressValueError:
            self.logger.exception("Invalid multicast address provided")
            self.multicast_test_status = False
            return False

    def communicate_with_target(self) -> bool:
        if not self.ip_address:
            self.logger.error("No target IP specified for communication test")
            self.net_test_flag = False
            return False

        try:
            ping_result = self._runner.ping(self.ip_address)
            if ping_result != 0:
                self.net_test_flag = False
                return False
            self.net_test_flag = True
            return True
        except Exception:  # pragma: no cover - defensive
            self.logger.exception("Error while attempting to ping target")
            self.net_test_flag = False
            return False


__all__ = ["NetworkCommandRunner", "NetworkTestService", "NetworkTestResult"]
