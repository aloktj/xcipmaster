"""Core controller for the CIP command-line interface."""

import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from scapy import all as scapy_all
from tabulate import tabulate

from xcipmaster.comm import (
    CommunicationManager,
    default_client_factory,
    default_thread_factory,
)
from xcipmaster.config import CIPConfigService
from xcipmaster.fields import (
    FieldFormatter,
    FieldFormattingError,
    FieldMutator,
    FieldMutationError,
    WaveformError,
    WaveformManager,
)
from xcipmaster.network import NetworkCommandRunner, NetworkTestService
from xcipmaster.paths import default_config_directory

from .ui import UIUtilities


log_dir = "./log"
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    filename="./log/app.log",
)


class CLI(UIUtilities):
    def __init__(
        self,
        config_service: Optional[CIPConfigService] = None,
        network_service: Optional[NetworkTestService] = None,
        comm_manager: Optional[CommunicationManager] = None,
        *,
        field_mutator: Optional[FieldMutator] = None,
        field_formatter: Optional[FieldFormatter] = None,
        waveform_manager: Optional[WaveformManager] = None,
        test_mode: bool = False,
    ):
        """Create a CLI controller with optional service overrides.

        ``config_service``, ``network_service``, and ``comm_manager`` default to
        their production implementations.  Tests can inject light-weight fakes,
        for example ``CLI(config_service=my_fake, test_mode=True)``, to avoid
        touching the real filesystem or network.  ``test_mode`` additionally
        suppresses the interactive prompts triggered by
        :func:`_initialize_controller`.  Communication tests can run the
        handshake and IO logic synchronously via
        :meth:`CommunicationManager.run_once` while injecting synchronous
        factories.
        """

        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)

        if config_service is None:
            config_service = CIPConfigService(logger=self.logger)
        self.config_service = config_service

        if network_service is None:
            network_service = NetworkTestService(
                logger=self.logger, runner=NetworkCommandRunner()
            )
        self.network_service = network_service

        if comm_manager is None:
            comm_manager = CommunicationManager(
                self.config_service,
                self.network_service,
                logger=self.logger,
                client_factory=default_client_factory,
                thread_factory=default_thread_factory,
            )
        self.comm_manager = comm_manager

        if field_mutator is None:
            field_mutator = FieldMutator()
        self.field_mutator = field_mutator

        if field_formatter is None:
            field_formatter = FieldFormatter()
        self.field_formatter = field_formatter

        if waveform_manager is None:
            waveform_manager = WaveformManager(
                lambda: self.ot_packet,
                self.field_mutator,
                lock=self.comm_manager.lock,
            )
        self.wave_manager = waveform_manager
        self.cip_test_flag = True
        self.logger.info("Initializing LoggedClass")
        self.time_zone = self.get_system_timezone()
        self.test_mode = test_mode
        self.target_ip = "10.0.1.1"
        self.multicast_ip = "239.192.1.3"
        self.default_config_path = str(default_config_directory())

    @property
    def ot_packet(self):
        packet = self.config_service.get_packet_instance("OT_EO")
        return packet if packet is not None else self.config_service.OT_packet

    @ot_packet.setter
    def ot_packet(self, value):
        if hasattr(self.config_service, "set_packet_instance"):
            self.config_service.set_packet_instance("OT_EO", value)
        else:  # pragma: no cover - defensive fallback
            self.config_service.OT_packet = value

    @property
    def to_packet(self):
        packet = self.config_service.get_packet_instance("TO")
        return packet if packet is not None else self.config_service.TO_packet

    @to_packet.setter
    def to_packet(self, value):
        if hasattr(self.config_service, "set_packet_instance"):
            self.config_service.set_packet_instance("TO", value)
        else:  # pragma: no cover - defensive fallback
            self.config_service.TO_packet = value

    @property
    def lock(self):
        return self.comm_manager.lock

    @property
    def enable_auto_reconnect(self):
        return self.comm_manager.enable_auto_reconnect

    @property
    def start_comm_thread_instance(self):
        return self.comm_manager.start_comm_thread_instance


    ###-------------------------------------------------------------###
    ###                     Multicast Route                         ###
    ###-------------------------------------------------------------###
    
    def get_multicast_route(self):
        return self.network_service.get_multicast_route()

    def check_multicast_support(self):
        return self.network_service.check_multicast_support()

    ###-------------------------------------------------------------###
    ###                     Configuration                           ###
    ###-------------------------------------------------------------###
 
    ###############################################################
    # Testing only
    ################################################################
    
    
    def list_files_in_config_folder(self, config_folder: str):
        xml_files = self.config_service.list_files_in_config_folder(config_folder)

        if not xml_files:
            click.echo("No files found in the config folder")
            return []

        click.echo("Detected Files in Config Folder:")
        click.echo("")

        for idx, path in enumerate(xml_files, start=1):
            click.echo(f" {idx}. {path.name}")

        click.echo("")
        return list(xml_files)

    def _resolve_cip_config_path(self, config_path: str):
        if hasattr(self.config_service, "resolve_cip_config_path"):
            resolved_path = self.config_service.resolve_cip_config_path(config_path)
            if resolved_path is None:
                click.echo("CIP configuration path is invalid or ambiguous.")
                return None
            return str(resolved_path)
        return str(config_path)

    def cip_config(self, config_path: str, *, force: bool = False):
        self.logger.info("Executing cip_config function")

        click.echo("╔══════════════════════════════════════════╗")
        click.echo("║          CIP Configuration               ║")
        click.echo("╚══════════════════════════════════════════╝")

        resolved_path_str = self._resolve_cip_config_path(str(config_path))
        if resolved_path_str is None:
            click.echo("Unable to load CIP configuration. Check the provided path.")
            click.echo("")
            self.cip_test_flag = False
            return False

        resolved_path = Path(resolved_path_str)

        current_path = getattr(self.config_service, "cip_xml_path", None)
        overall_valid = getattr(self.config_service, "overall_cip_valid", False)
        if (
            not force
            and current_path is not None
            and current_path == resolved_path
            and overall_valid
        ):
            click.echo(f"Using cached CIP configuration: {resolved_path}")
            click.echo("")
            self.cip_test_flag = True
            self.default_config_path = str(resolved_path)
            return True

        result = self.config_service.load_configuration(str(resolved_path))
        if not result.resolved_path:
            click.echo("Unable to load CIP configuration. Check the provided path.")
            click.echo("")
            self.cip_test_flag = False
            return False

        click.echo(f"Using CIP configuration: {result.resolved_path}")
        click.echo("")
        time.sleep(0.1)

        click.echo("===== Testing CIP Configuration =====")

        table_rows = list(self.config_service.latest_results())
        if table_rows:
            click.echo(
                tabulate(table_rows, headers=["Test Case", "Status"], tablefmt="fancy_grid")
            )

        if result.success:
            click.echo("All tests passed successfully.")
            click.echo("")
            self.cip_test_flag = True
            self.default_config_path = str(result.resolved_path)
            return True

        click.echo("Some tests failed. See output above for details.")
        click.echo("")
        self.cip_test_flag = False
        return False

    def ensure_configuration(self, config_path: Optional[str] = None, *, force: bool = False) -> bool:
        """Ensure a CIP configuration is loaded, optionally from *config_path*."""

        path_to_use = config_path or self.default_config_path
        if not path_to_use:
            click.echo("No CIP configuration path available.")
            return False

        resolved_path_str = self._resolve_cip_config_path(path_to_use)
        if resolved_path_str is None:
            return False

        resolved_path = Path(resolved_path_str)
        current_path = getattr(self.config_service, "cip_xml_path", None)
        overall_valid = getattr(self.config_service, "overall_cip_valid", False)

        if (
            not force
            and current_path is not None
            and current_path == resolved_path
            and overall_valid
        ):
            return True

        return self.cip_config(str(resolved_path), force=force)

    def config_network(self, target_ip: str, multicast_ip: str):
        self.logger.info("Executing config_network function")
        click.echo("╔══════════════════════════════════════════╗")
        click.echo("║        Network Configuration             ║")
        click.echo("╚══════════════════════════════════════════╝")
        click.echo("")

        time.sleep(0.1)

        result = self.network_service.configure(target_ip, multicast_ip)

        if result.target_ip:
            click.echo(f"Target IP address: {result.target_ip}")
        if result.multicast_ip:
            click.echo(f"Multicast group address: {result.multicast_ip}")

        click.echo("\n===== Testing Communication with Target =====")
        time.sleep(1)

        table_data = [["Communication Test Result", "Status"]]
        table_data.extend(result.tests)
        click.echo("\n" + tabulate(table_data, headers="firstrow", tablefmt="fancy_grid"))
        click.echo("")

        if result.success:
            time.sleep(0.1)
            self.target_ip = target_ip
            self.multicast_ip = multicast_ip
            return True

        click.echo("===== Failed Network Configuration Test =====")
        click.echo("")
        return False

    def ensure_network_configuration(
        self,
        target_ip: Optional[str] = None,
        multicast_ip: Optional[str] = None,
        *,
        force: bool = False,
    ) -> bool:
        """Ensure network tests have succeeded for the requested addresses."""

        selected_target = target_ip or self.target_ip
        selected_multicast = multicast_ip or self.multicast_ip

        current_ip = getattr(self.network_service, "ip_address", None)
        current_multicast = getattr(self.network_service, "user_multicast_address", None)
        net_flag = getattr(self.network_service, "net_test_flag", False)
        multicast_flag = getattr(self.network_service, "multicast_test_status", False)

        if (
            not force
            and current_ip == selected_target
            and current_multicast == selected_multicast
            and net_flag
            and multicast_flag
        ):
            self.target_ip = selected_target
            self.multicast_ip = selected_multicast
            return True

        success = self.config_network(selected_target, selected_multicast)
        if success:
            self.target_ip = selected_target
            self.multicast_ip = selected_multicast
        return success
            
            
    ############ Help Menu ############ 
    def help_menu(self):
        self.logger.info("Executing help_menu function")
        click.echo("\nAvailable commands:")
        
        commands = [
            ("start", "Validate configuration, test networking, and start communication"),
            ("stop", "Stop Communication"),
            ("auto", "Switch to automatic communication"),
            ("man", "Switch to manual communication (usage: start,stop Commands)"),
            ("set <name> <val>", "Set a field value"),
            ("clear <name>", "Clear a field value"),
            ("get <name>", "Get the current value of a field"),
            ("frame", "Print the packet header and payload"),
            ("fields", "Display the field names"),
            ("wave <name> <max_val> <min_val> <period(ms)>", "Wave a field value"),
            ("stop_wave <name>", "Stop waving for a field value"),
            ("tria <name> <max_val> <min_val> <period(ms)>", "Wave a field value with a triangular waveform"),
            ("box <name> <max_val> <min_val> <period(ms)> <duty_cycle>", "Wave a field value with a square/rectangular waveform"),
            ("live <refresh_rate(ms)>", "Display real-time field data of the specified packet class"),
            ("cip-config", "Select and validate a CIP configuration file"),
            ("test-net --target-ip <ip> --multicast-ip <ip>", "Run network configuration tests"),
            ("set-net [--target-ip <ip>] [--multicast-ip <ip>]", "Update stored network addresses and rerun tests"),
            ("log", "Print the recent 100 log events"),
            ("exit", "Exit the application"),
            ("help", "Display this help menu")
        ]
        
        headers = ["Command Usage", "Command Description"]
        table = tabulate(commands, headers=headers, tablefmt="fancy_grid", colalign=("left", "left"))
        click.echo(table)
    



    ###-------------------------------------------------------------###
    ###                     Modification                            ###
    ###-------------------------------------------------------------###

    def _resolve_packet_for_field(self, field_name):
        if hasattr(self.ot_packet.__class__, field_name):
            return self.ot_packet, "OT_EO"
        if hasattr(self.to_packet.__class__, field_name):
            return self.to_packet, "TO"
        return None, None

    def MPU_heartbeat(self, field_name,field_value):
        self.logger.info("MPU_HeartBeat function executing")
        self.logger.info(f"field name:{field_name}")
        self.logger.info(f"field value:{field_value}")
        
        if hasattr(self.ot_packet,field_name):
            field = getattr(self.ot_packet.__class__, field_name)
            if isinstance(field, scapy_all.ByteField):
                    setattr(self.ot_packet, field_name, field_value)
                    self.logger.info("MPU_HeartBeat set")
            else:
                self.logger.warning("Heartbeat is not ByteField type")
        else:
            self.logger.warning(f"There is no HearBeat with the name: {field_name}")

    
    def set_field(self, field_name, field_value):
        self.logger.info("Executing set_field function")
        self.stop_wave(field_name)
        packet, _ = self._resolve_packet_for_field(field_name)
        if packet is None:
            print(f"Field {field_name} not found.")
            return False

        try:
            with self.lock:
                self.field_mutator.set_value(packet, field_name, field_value)
        except FieldMutationError as exc:
            print(str(exc))
            return False

        print(f"Set {field_name} to {field_value}")
        return True

    def clear_field(self, field_name):
        self.logger.info("Executing clear_field function")
        self.stop_wave(field_name)
        packet, _ = self._resolve_packet_for_field(field_name)
        if packet is None:
            print(f"Field {field_name} not found.")
            return False

        try:
            with self.lock:
                self.field_mutator.clear_value(packet, field_name)
        except FieldMutationError as exc:
            print(str(exc))
            return False

        print(f"Cleared {field_name}")
        return True

    def wave_field(self, field_name, max_value, min_value, period_ms):
        self.logger.info("Executing wave_field function")
        try:
            self.wave_manager.start_wave(field_name, max_value, min_value, period_ms)
        except WaveformError as exc:
            print(str(exc))
            return False

        print(
            f"Waving {field_name} from {min_value} to {max_value} every {period_ms} milliseconds."
        )
        return True

    def tria_field(self, field_name, max_value, min_value, period_ms):
        self.logger.info("Executing tria_field function")
        try:
            self.wave_manager.start_triangle_wave(field_name, max_value, min_value, period_ms)
        except WaveformError as exc:
            print(str(exc))
            return False

        print(
            f"Generating triangular wave for {field_name} every {period_ms} milliseconds."
        )
        return True

    def box_field(self, field_name, max_value, min_value, period_ms, duty_cycle):
        self.logger.info("Executing box_field function")
        try:
            self.wave_manager.start_square_wave(
                field_name, max_value, min_value, period_ms, duty_cycle
            )
        except WaveformError as exc:
            print(str(exc))
            return False

        print(
            f"Generating square wave for {field_name} with duty cycle {duty_cycle} every {period_ms} milliseconds."
        )
        return True

    def stop_wave(self, field_name):
        self.logger.info("Executing stop_wave function")
        if self.wave_manager.stop_wave(field_name):
            click.echo(f"\nWaving for '{field_name}' has been stopped.\n")
            return True
        return False

    def stop_all_thread(self):
        self.logger.info("Stopping all wave threads")
        stopped_fields = self.wave_manager.stop_all()
        for name in stopped_fields:
            click.echo(f"{self.stop_all_thread.__name__}: Waving for '{name}' has been stopped")
        if stopped_fields:
            self.logger.info("All wave threads have been successfully stopped")
        return bool(stopped_fields)

    def get_field(self, field_name):
        self.logger.info("Executing get_field function")
        timestamp = self.get_timestamp()
        click.echo("")
        click.echo(tabulate([[timestamp]], headers=["Timestamp", ""], tablefmt="fancy_grid"))

        packet, _ = self._resolve_packet_for_field(field_name)
        if packet is None:
            packet_type = "N/A"
            display_value = "Field not found"
        else:
            packet_type = packet.__class__.__name__
            try:
                field_value = self.field_formatter.format_value(packet, field_name)
                display_value = self.decrease_font_size(str(field_value))
            except FieldFormattingError as exc:
                display_value = str(exc)

        field_data = [(packet_type, field_name, display_value)]
        click.echo(
            tabulate(
                field_data,
                headers=["CIP-MSG Identifier", "Field Name", "Field Value"],
                tablefmt="fancy_grid",
            )
        )
        click.echo("")

    def get_big_endian_value(self, packet, field_name):
        return self.field_formatter.format_value(packet, field_name)

    def _format_packet_fields(self, packet):
        if packet is None:
            return []

        formatted = []
        for field in getattr(packet, "fields_desc", []):
            name = getattr(field, "name", "")
            if not name:
                continue
            try:
                value = self.field_formatter.format_value(packet, name)
                display = self.decrease_font_size(str(value))
            except FieldFormattingError as exc:
                display = str(exc)
            formatted.append((name, display))
        return formatted

    def print_frame(self):
        """Render the current OT and TO packets as hexadecimal frames."""

        self.logger.info("Executing print_frame function")

        packets = (("OT_EO", self.ot_packet), ("TO", self.to_packet))

        for label, packet in packets:
            if packet is None:
                click.echo(f"No {label} packet is currently loaded.")
                click.echo("")
                continue

            click.echo(f"{label} Packet Header and Payload:")

            try:
                hexdump_output = scapy_all.hexdump(packet, dump=True)
            except Exception as exc:  # pragma: no cover - defensive fallback
                self.logger.exception("Failed to render %s packet", label)
                click.echo(f"Unable to display {label} packet: {exc}")
                click.echo("")
                continue

            click.echo(hexdump_output)
            click.echo("")

    def print_packet_fields(self, title, packet, show_spares=False, subtype=None):
        # Organizing fields by type for the given packet
        fields_by_type = {}

        field_metadata = {}
        if subtype:
            for metadata in self.config_service.get_field_metadata(subtype):
                field_metadata[metadata["id"]] = metadata

        if field_metadata:
            for metadata in field_metadata.values():
                field_name = metadata["id"]
                if not show_spares and field_name.startswith("spare_"):
                    continue
                field_type = metadata["type"]
                fields_by_type.setdefault(field_type, []).append(field_name)
        elif packet is not None:
            for field in packet.fields_desc:
                field_type = type(field).__name__
                fields_by_type.setdefault(field_type, []).append(getattr(field, "name", ""))

        packet_table = []
        for field_type, field_names in fields_by_type.items():
            field_names = [name for name in field_names if name]
            field_str = ", ".join(field_names)
            if len(field_str) > 100:
                field_str = ""
                curr_len = 0
                for name in field_names:
                    if curr_len + len(name) + 2 > 100:
                        field_str += "\n" + name + ", "
                        curr_len = len(name) + 2
                    else:
                        field_str += name + ", "
                        curr_len += len(name) + 2
                field_str = field_str.rstrip(", ")

            packet_table.append([field_type, field_str])

        if not show_spares:
            packet_table = [row for row in packet_table if not row[0].startswith("spare_")]

        table_width = 100

        headers = ["Field Type", "Field Names"]
        colalign = ["left", "left"]
        title_header = f"{title}:"
        click.echo(title_header.center(table_width))
        click.echo(tabulate(packet_table, headers=headers, colalign=colalign, tablefmt="fancy_grid"))
        click.echo("")
        
    def list_fields(self):
        self.logger.info("Executing list_fields function")
        
        ot_packet = self.ot_packet
        ot_title = ot_packet.__class__.__name__ if ot_packet else "OT"
        self.print_packet_fields(ot_title, ot_packet, subtype="OT_EO")

        to_packet = self.to_packet
        to_title = to_packet.__class__.__name__ if to_packet else "TO"
        self.print_packet_fields(to_title, to_packet, subtype="TO")
        
    
    def get_system_timezone(self):
        # Get the system's timezone
        timezone = time.tzname[0]  # Get the timezone abbreviation
        return timezone
    
    def get_timestamp(self):
        # Get the current timestamp in the desired format
        timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S:%f")[:-3]  # Remove microseconds
        location_code = self.time_zone
        return f"{timestamp} {location_code}"
    
    def decrease_font_size(self, text):
        # Add special characters or spaces to decrease font size
        return " " + text
    
    
        
    def live_field_data(self, refresh_ms):
        self.logger.info("Executing live_field_data function")
        refresh_rate = float(refresh_ms)
        click.echo("")
        try:
            while True:
                # Print timestamp
                print(*"=" * 50, sep="")
                click.echo("")
                timestamp = self.get_timestamp()
                click.echo(tabulate([[timestamp]], headers=["Timestamp", ""], tablefmt="fancy_grid"))
                
                class_name_OT = self.ot_packet.__class__.__name__
                field_data_OT = self._format_packet_fields(self.ot_packet)
                click.echo(f"\t\t\t {class_name_OT} \t\t\t")
                click.echo(tabulate(field_data_OT, headers=["Field Name", "Field Value"], tablefmt="fancy_grid"))
                click.echo("")

                class_name_TO = self.to_packet.__class__.__name__
                field_data_TO = self._format_packet_fields(self.to_packet)
                click.echo(f"\t\t\t {class_name_TO} \t\t\t")
                click.echo(tabulate(field_data_TO, headers=["Field Name", "Field Value"], tablefmt="fancy_grid"))
                time.sleep(refresh_rate/1000)  # Adjust the delay as needed for real-time display
                click.echo("")
                print(*"=" * 50, sep="")
        except KeyboardInterrupt:
            print("\nExiting live field data display...")
            return
   
    
    ########################################################################
    # Under Test
    ########################################################################

    def print_last_logs(self):
        log_file_path = "./log/app.log"
        if os.path.exists(log_file_path):
            with open(log_file_path, "r") as log_file:
                lines = log_file.readlines()
                last_100_lines = lines[-100:]
                click.echo("Last 100 lines of app.log:")
                for line in last_100_lines:
                    click.echo(line.strip())
    

