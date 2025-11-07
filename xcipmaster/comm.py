"""Communication management services for XCIP Master."""
from __future__ import annotations

import calendar
import logging
import threading
import time
from typing import Any, Callable, Optional

from thirdparty.scapy_cip_enip.tgv2020 import Client
from scapy import all as scapy_all

from .config import CIPConfigService
from .network import NetworkTestService


ClientFactory = Callable[..., Any]
ThreadFactory = Callable[..., threading.Thread]


def default_client_factory(
    *,
    ip_address: str,
    multicast_address: str,
    ot_param: int,
    to_param: int,
) -> Client:
    """Create a production CIP client instance.

    The factory centralises the creation logic so tests can supply a synchronous
    fake without importing the heavy Scapy based implementation.
    """

    client = Client(IPAddr=ip_address, MulticastGroupIPaddr=multicast_address)
    client.ot_connection_param = ot_param
    client.to_connection_param = to_param
    return client


def default_thread_factory(*, target: Callable[[], None], name: Optional[str] = None) -> threading.Thread:
    """Create the background thread used in production."""

    return threading.Thread(target=target, name=name, daemon=True)


class CommunicationManager:
    """Manage CIP communication lifecycles."""

    def __init__(
        self,
        config_service: CIPConfigService,
        network_service: NetworkTestService,
        logger: Optional[logging.Logger] = None,
        *,
        client_factory: Optional[ClientFactory] = None,
        thread_factory: Optional[ThreadFactory] = None,
    ):
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.config_service = config_service
        self.network_service = network_service
        self.lock = threading.Lock()
        self.stop_comm_events = threading.Event()
        self.start_comm_thread_instance: Optional[threading.Thread] = None
        self.enable_auto_reconnect = False
        self.clMPU_CIP_Server = None
        self.bCIPErrorOccured = False
        self.client_factory: ClientFactory = client_factory or default_client_factory
        self.thread_factory: ThreadFactory = thread_factory or default_thread_factory

    def calculate_connection_params(self):
        ot_size = None
        to_size = None

        try:
            if self.config_service.ot_eo_assemblies is not None:
                ot_size = int(self.config_service.ot_eo_assemblies.attrib.get("size"))
            if self.config_service.to_assemblies is not None:
                to_size = int(self.config_service.to_assemblies.attrib.get("size"))
        except Exception:  # pragma: no cover - defensive
            self.logger.exception("Unable to fetch assembly size")

        if ot_size is not None:
            ot_connection_param = 0x4800 | ((ot_size // 8) + 6)
        else:
            ot_connection_param = None
        if to_size is not None:
            to_connection_param = 0x2800 | ((to_size // 8) + 6)
        else:
            to_connection_param = None

        return (ot_connection_param, to_connection_param)

    def manage_io_communication(self, clMPU_CIP_Server):
        self.logger.info("Executing ManageCIP_IOCommunication function")

        MPU_CTCMSAlive = int(0)
        CIP_AppCounter = 65500
        bCIPErrorOccured = bool(False)

        while not bCIPErrorOccured:
            pkgCIP_IO = clMPU_CIP_Server.recv_UDP_ENIP_CIP_IO(False, 0.5)

            if pkgCIP_IO is not None:
                self.logger.info("manage_io_communication: Detected incoming stream")

                self.lock.acquire()
                self.config_service.TO_packet = self.config_service.TO_packet_class(
                    (pkgCIP_IO.payload.load)
                )
                self.lock.release()

                self.lock.acquire()
                if self.config_service.TO_packet is not None:
                    self.logger.info("manage_io_communication: Parsed TO packet data")
                    if MPU_CTCMSAlive >= 255:
                        MPU_CTCMSAlive = 0
                    else:
                        MPU_CTCMSAlive += 1

                    self._set_heartbeat("MPU_CTCMSAlive", MPU_CTCMSAlive)

                    if hasattr(self.config_service.OT_packet, "MPU_CDateTimeSec"):
                        setattr(
                            self.config_service.OT_packet,
                            "MPU_CDateTimeSec",
                            calendar.timegm(time.gmtime()),
                        )
                    clMPU_CIP_Server.send_UDP_ENIP_CIP_IO(
                        CIP_Sequence_Count=CIP_AppCounter,
                        Header=1,
                        AppData=self.config_service.OT_packet,
                    )

                    if CIP_AppCounter < 65535:
                        CIP_AppCounter += 1
                    else:
                        CIP_AppCounter = 0
                else:
                    self.logger.warning("manage_io_communication: Failed to parse TO packet")
                    bCIPErrorOccured = True

                self.lock.release()

            else:
                self.logger.warning(
                    "manage_io_communication: Not possible to convert CIP IO frame into scapy packet class"
                )
                bCIPErrorOccured = True
                return bCIPErrorOccured

        return bCIPErrorOccured

    def start(self):
        self.logger.info("Starting CIP communication")

        if (
            self.start_comm_thread_instance is not None
            and self.start_comm_thread_instance.is_alive()
        ):
            self.logger.info("start: Communication thread already running; start request ignored")
            return

        if self.enable_auto_reconnect:
            self.logger.warning("Auto-Reconnect Detected")
        else:
            self.logger.warning("Manual Connect Detected")

        ot_param, to_param = self.calculate_connection_params()
        if ot_param is None or to_param is None:
            self.logger.warning("Connection parameters are not defined")
            return

        def start_comm_thread():
            while self.enable_auto_reconnect or not self.stop_comm_events.is_set():
                try:
                    self.logger.info("Executing start communication thread")
                    self.run_once(ot_param=ot_param, to_param=to_param)
                except (ConnectionError, Exception) as exc:
                    self.logger.error("Connection error: %s", exc)
                    if self.enable_auto_reconnect and not self.stop_comm_events.is_set():
                        self.logger.info("Auto-reconnect is enabled. Retrying in 2 seconds...")
                        time.sleep(2)
                        continue
                    self.logger.info("Auto-reconnect is disabled. Exiting communication thread.")
                    break

                if self.stop_comm_events.is_set():
                    break

                if not self.enable_auto_reconnect:
                    self.logger.info("start: Auto reconnect disabled, exiting thread")
                    break

                self.logger.info("Auto-reconnect is enabled. Retrying in 2 seconds...")
                time.sleep(2)

                if self.stop_comm_events.is_set():
                    break

            self.logger.info("start: Thread has finished execution")

        self.stop_comm_events.clear()
        try:
            thread = self.thread_factory(
                target=start_comm_thread,
                name="CIPCommunicationThread",
            )
        except TypeError:
            thread = self.thread_factory(start_comm_thread)
        self.start_comm_thread_instance = thread
        self.start_comm_thread_instance.start()

    def run_once(
        self,
        *,
        ot_param: Optional[int] = None,
        to_param: Optional[int] = None,
    ) -> bool:
        """Run a single communication cycle synchronously.

        The helper enables unit tests to exercise the handshake and IO logic
        without spawning background threads.
        """

        if ot_param is None or to_param is None:
            ot_param, to_param = self.calculate_connection_params()
            if ot_param is None or to_param is None:
                self.logger.warning("Connection parameters are not defined")
                return False

        client = self._create_client(ot_param, to_param)
        self.clMPU_CIP_Server = client
        handshake_success = False
        self.bCIPErrorOccured = False

        try:
            if not getattr(client, "connected", False):
                self.logger.warning("start: Unable to establish session")
                raise ConnectionError("Failed to establish session")

            self.logger.info("start: Established session %s", client.connected)

            bForwoardOpenRspIsOK = client.forward_open()
            if bForwoardOpenRspIsOK:
                self.logger.info("start: Forward Open OK")
            else:
                self.logger.warning("start: Forward Open request failed")
                raise ConnectionError("Forward Open request failed")

            handshake_success = True
            self.bCIPErrorOccured = self.manage_io_communication(client)

            if not self.bCIPErrorOccured and hasattr(client, "forward_close"):
                client.forward_close()

            return handshake_success
        finally:
            if hasattr(client, "close"):
                client.close()
            self.clMPU_CIP_Server = None

    def _create_client(self, ot_param: int, to_param: int):
        try:
            client = self.client_factory(
                ip_address=self.network_service.ip_address,
                multicast_address=self.network_service.user_multicast_address,
                ot_param=ot_param,
                to_param=to_param,
            )
        except TypeError:
            client = self.client_factory(
                self.network_service.ip_address,
                self.network_service.user_multicast_address,
                ot_param,
                to_param,
            )

        if hasattr(client, "ot_connection_param"):
            client.ot_connection_param = ot_param
        if hasattr(client, "to_connection_param"):
            client.to_connection_param = to_param

        return client

    def _set_heartbeat(self, field_name: str, field_value: int) -> None:
        packet = self.config_service.OT_packet
        if packet is None:
            return
        if hasattr(packet, field_name):
            field = getattr(packet.__class__, field_name)
            if isinstance(field, scapy_all.ByteField):
                setattr(packet, field_name, field_value)

    def enable_auto(self):
        self.logger.info("Automatic communication enabled")
        self.enable_auto_reconnect = True

    def disable_auto(self):
        self.logger.info("Automatic communication disabled")
        self.enable_auto_reconnect = False
        self.stop()

    def stop(self):
        self.logger.info("Stopping communication thread")
        if self.stop_comm_events is not None:
            self.stop_comm_events.set()

        try:
            if self.clMPU_CIP_Server is not None:
                try:
                    if hasattr(self.clMPU_CIP_Server, "forward_close"):
                        self.clMPU_CIP_Server.forward_close()
                except Exception as exc:
                    self.logger.error("Error closing CIP connection: %s", exc)

                try:
                    self.clMPU_CIP_Server.close()
                    self.logger.info("Server connection closed successfully")
                except Exception as exc:
                    self.logger.error("Error closing server connection: %s", exc)

            if (
                self.start_comm_thread_instance is not None
                and self.start_comm_thread_instance.is_alive()
            ):
                self.start_comm_thread_instance.join(timeout=5)
                if self.start_comm_thread_instance.is_alive():
                    self.logger.warning("Communication thread did not stop within timeout")
                else:
                    self.logger.info("Communication thread stopped successfully")
                    self.start_comm_thread_instance = None

            self.logger.info("Communication thread stopped")
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.error("Unexpected error while stopping communication: %s", exc)
        finally:
            if (
                self.start_comm_thread_instance is not None
                and self.start_comm_thread_instance.is_alive()
            ):
                self.logger.warning("Communication thread is still running")
            else:
                self.start_comm_thread_instance = None


__all__ = [
    "CommunicationManager",
    "default_client_factory",
    "default_thread_factory",
]
