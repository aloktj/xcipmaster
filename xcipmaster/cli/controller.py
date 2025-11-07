"""Core controller for the CIP command-line interface."""

import logging
import os
import string
import struct
import time
from datetime import datetime
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
from xcipmaster.network import NetworkCommandRunner, NetworkTestService

from .ui import UIUtilities
from .waveforms import WaveformUtilities


log_dir = "./log"
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    filename="./log/app.log",
)


class CLI(UIUtilities, WaveformUtilities):
    def __init__(
        self,
        config_service: Optional[CIPConfigService] = None,
        network_service: Optional[NetworkTestService] = None,
        comm_manager: Optional[CommunicationManager] = None,
        *,
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
        self.thread_dict = {}  # Dictionary to store wave threads
        self.stop_events = {}
        self.cip_test_flag = True
        self.logger.info("Initializing LoggedClass")
        self.time_zone = self.get_system_timezone()
        self.test_mode = test_mode

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
        return [str(path) for path in xml_files]

    def _resolve_cip_config_path(self, config_path: str):
        resolved_path = self.config_service.resolve_cip_config_path(config_path)
        if resolved_path is None:
            click.echo("CIP configuration path is invalid or ambiguous.")
            return None
        return str(resolved_path)

    def cip_config(self, config_path: str):
        self.logger.info("Executing cip_config function")

        click.echo("╔══════════════════════════════════════════╗")
        click.echo("║          CIP Configuration               ║")
        click.echo("╚══════════════════════════════════════════╝")

        result = self.config_service.load_configuration(str(config_path))
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
            return True

        click.echo("Some tests failed. See output above for details.")
        click.echo("")
        self.cip_test_flag = False
        return False
        
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
            return True

        click.echo("===== Failed Network Configuration Test =====")
        click.echo("")
        return False
            
            
    ############ Help Menu ############ 
    def help_menu(self):
        self.logger.info("Executing help_menu function")
        click.echo("\nAvailable commands:")
        
        commands = [
            ("start --config <path> --target-ip <ip> --multicast-ip <ip>", "Validate configuration, test networking, and start communication"),
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
            ("cip-config --config <path>", "Run CIP configuration tests"),
            ("test-net --target-ip <ip> --multicast-ip <ip>", "Run network configuration tests"),
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
        self.lock.acquire()
        if hasattr(self.ot_packet, field_name):
            field = getattr(self.ot_packet.__class__, field_name)
            if isinstance(field, scapy_all.IEEEFloatField):
                try:
                    byte_array = struct.pack('f', float(field_value))
                    reversed_byte_array = byte_array[::-1]
                    bE_field_value = struct.unpack('f', reversed_byte_array)[0] #Big endian field value
                    setattr(self.ot_packet, field_name, bE_field_value)
                    print(f"Set {field_name} to {field_value}")
                except ValueError:
                    print(f"Field {field_name} expects a float value.")
            elif isinstance(field, scapy_all.BitField):
                if field_value in ['0', '1']:
                    setattr(self.ot_packet, field_name, int(field_value))
                    print(f"Set {field_name} to {field_value}")
                else:
                    print(f"Field {field_name} expects a value of either '0' or '1'.")
            elif isinstance(field, scapy_all.ByteField):
                if field_value.startswith('0x') and len(field_value) == 4 and all(
                        c in string.hexdigits for c in field_value[2:]):
                    int_value = int(field_value, 16)
                    setattr(self.ot_packet, field_name, int_value)
                    print(f"Set {field_name} to {field_value}")
                elif field_value.isdigit():
                    int_value = int(field_value)
                    if 0 <= int_value <= 0xFF:
                        setattr(self.ot_packet, field_name, int_value)
                        print(f"Set {field_name} to {field_value}")
                    else:
                        print(f"Field {field_name} expects an integer value between 0 and 255.")
                else:
                    print(
                        f"Field {field_name} expects an integer value or a hexadecimal value in the format '0x00' to '0xFF'.")
            
            elif isinstance(field, scapy_all.ShortField):
                if field_value.startswith('0x') and len(field_value) == 6 and all(
                    c in string.hexdigits for c in field_value[2:]):
                    int_value = int(field_value, 16)
                    setattr(self.ot_packet, field_name, int(int_value.to_bytes(2, byteorder='big')))
                    print(f"Set {field_name} to {field_value}")
                elif field_value.isdigit():
                    int_value = int(field_value)
                    if 0 <= int_value <= 0xFFFF:
                        try:
                            byte_array = int_value.to_bytes(2, byteorder='big')
                            reversed_byte_array = byte_array[::-1]
                            converted_value = int.from_bytes(reversed_byte_array, byteorder='big')
                            setattr(self.ot_packet, field_name, converted_value)
                        except:
                            print("Error in setting ShortField")
                        print(f"Set {field_name} to {field_value}")
                    else:
                        print(f"Field {field_name} expects an integer value between 0 and 65535.")
                else:
                    print(f"Field {field_name} expects an integer value or a hexadecimal value in the format '0x0000' to '0xFFFF'.")
            
            ###
            elif isinstance(field, scapy_all.LEShortField):

                if field_value.startswith('0x') and len(field_value) == 4 and all(
                    c in string.hexdigits for c in field_value[2:]):

                    int_value = int(field_value, 16)
                    setattr(self.ot_packet, field_name, int_value.to_bytes(2, byteorder='big'))
                    print(f"Set {field_name} to {field_value}")

                elif field_value.isdigit():

                    int_value = int(field_value)
                    if 0 <= int_value <= 0xFFFF:
                        setattr(self.ot_packet, field_name, int_value) 
                        print(f"Set {field_name} to {field_value}")

                    else:
                        print(f"Field {field_name} expects an integer value between 0 and 65535.")

                else:

                    print(f"Field {field_name} expects an integer value or a hexadecimal value in the format '0x0000' to '0xFFFF'.")
                            
            ###
            
            elif isinstance(field, scapy_all.IEEEDoubleField):

                if field_value.startswith('0x'):

                    int_value = int(field_value, 16)

                    if 0 <= int_value <= (2**64 - 1):  

                        setattr(self.ot_packet, field_name, int_value)

                        print(f"Set {field_name} to {field_value}")

                    else:

                        print("Value out of range for IEEEDoubleField")

                elif field_value.isdigit():

                    int_value = float(field_value)

                    if 0 <= int_value <= (2**64 - 1):

                        setattr(self.ot_packet, field_name, int_value)  

                        print(f"Set {field_name} to {field_value}")

                    else:

                        print("Value out of range for IEEEDoubleField")

                else:

                    print("Field value must be a number for IEEEDoubleField")
            
            
            elif isinstance(field, scapy_all.StrFixedLenField):
                if isinstance(field_value, str):
                    field_bytes = field_value.encode()
                elif isinstance(field_value, bytes):
                    field_bytes = field_value
                else:
                    print(f"Field {field_name} expects a string or bytes value.")
                    field_bytes = None

                if field_bytes is not None:
                    if len(field_bytes) <= field.length_from(self.ot_packet):
                        setattr(self.ot_packet, field_name, field_bytes)
                        print(f"Set {field_name} to {field_bytes}")
                    else:
                        print(f"Field {field_name} expects a string of length up to {field.length_from(self.ot_packet)}.")
            else:
                print(f"Field {field_name} is not of type IEEEFloatField, BitField, ByteField, or StrFixedLenField and "
                      f"cannot be set.")
        else:
            print(f"Field {field_name} not found.")
            
        self.lock.release()
        
       
    def clear_field(self, field_name):
        self.logger.info("Executing clear_field function")
        self.stop_wave(field_name)
        if hasattr(self.ot_packet, field_name):
            field = getattr(self.ot_packet.__class__, field_name)
            if isinstance(field, scapy_all.IEEEFloatField) or isinstance(field, scapy_all.BitField) or isinstance(field, scapy_all.ByteField):
                setattr(self.ot_packet, field_name, 0)
                print(f"Cleared {field_name}")
            elif isinstance(field, scapy_all.StrFixedLenField):
                setattr(self.ot_packet, field_name, b'')
                print(f"Cleared {field_name}")
            else:
                print(f"Cannot clear field {field_name}: unsupported field type.")
        else:
            print(f"Field {field_name} not found.")
            
    def get_field(self, field_name):
        self.logger.info("Executing get_field function")
        timestamp = self.get_timestamp()
        click.echo("")
        click.echo(tabulate([[timestamp]], headers=["Timestamp", ""], tablefmt="fancy_grid"))
        
        if hasattr(self.ot_packet, field_name):
            field_value = self.get_big_endian_value(self.ot_packet, field_name)
            packet_type = self.ot_packet.__class__.__name__
            field_data = [(packet_type, field_name, self.decrease_font_size(str(field_value)))]
            
        elif hasattr(self.to_packet, field_name):
            field_value = self.get_big_endian_value(self.to_packet, field_name)
            packet_type = self.to_packet.__class__.__name__
            field_data = [(packet_type, field_name, self.decrease_font_size(str(field_value)))]
            
        else:
            packet_type = "N/A"
            field_data = [(packet_type, field_name, "Field not found")]
        
        click.echo(tabulate(field_data, headers=["CIP-MSG Identifier", "Field Name", "Field Value"], tablefmt="fancy_grid"))
        click.echo("")
          
    def get_big_endian_value(self, packet, field_name):
        field = getattr(packet.__class__, field_name)
        field_value = getattr(packet, field_name)

        if isinstance(field, scapy_all.IEEEFloatField):
            byte_array = struct.pack('f', float(field_value))
            reversed_byte_array = byte_array[::-1]
            bE_field_value = struct.unpack('f', reversed_byte_array)[0]  # Big endian field value
            return bE_field_value

        elif isinstance(field, scapy_all.ShortField):
            byte_array = int(field_value).to_bytes(2, byteorder='big')
            reversed_byte_array = byte_array[::-1]
            bE_field_value = int.from_bytes(reversed_byte_array, byteorder='big')
            return bE_field_value

        elif isinstance(field, scapy_all.ByteField):
            byte_array = int(field_value).to_bytes(1, byteorder='big')
            reversed_byte_array = byte_array[::-1]
            bE_field_value = int.from_bytes(reversed_byte_array, byteorder='big')
            return bE_field_value

        elif isinstance(field, scapy_all.IntField):
            byte_array = int(field_value).to_bytes(4, byteorder='big')
            reversed_byte_array = byte_array[::-1]
            bE_field_value = int.from_bytes(reversed_byte_array, byteorder='big')
            return bE_field_value

        elif isinstance(field, scapy_all.LongField):
            byte_array = int(field_value).to_bytes(8, byteorder='big')
            reversed_byte_array = byte_array[::-1]
            bE_field_value = int.from_bytes(reversed_byte_array, byteorder='big')
            return bE_field_value

        elif isinstance(field, scapy_all.StrField):
            return field_value

        else:
            return field_value
    
    def print_frame(self):
        # Print timestamp
        print(*"=" * 50, sep="")
        click.echo("")
        timestamp = self.get_timestamp()
        click.echo(tabulate([[timestamp]], headers=["Timestamp", ""], tablefmt="fancy_grid"))
        self.lock.acquire()
        class_name_OT = self.ot_packet.__class__.__name__
        field_data_OT = [(field.name, self.decrease_font_size(str(self.get_big_endian_value(self.ot_packet, field.name)))) for field in self.ot_packet.fields_desc]
        self.lock.release()
        click.echo(f"\t\t\t {class_name_OT} \t\t\t")
        click.echo(tabulate(field_data_OT, headers=["Field Name", "Field Value"], tablefmt="fancy_grid"))
        click.echo("")
        
        self.lock.acquire()
        class_name_TO = self.to_packet.__class__.__name__
        field_data_TO = [(field.name, self.decrease_font_size(str(self.get_big_endian_value(self.to_packet, field.name)))) for field in self.to_packet.fields_desc]
        self.lock.release()
        click.echo(f"\t\t\t {class_name_TO} \t\t\t")
        click.echo(tabulate(field_data_TO, headers=["Field Name", "Field Value"], tablefmt="fancy_grid"))
        click.echo("")
        print(*"=" * 50, sep="")
    
    
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
                field_data_OT = [(field.name, self.decrease_font_size(str(getattr(self.ot_packet, field.name)))) for field in self.ot_packet.fields_desc]
                click.echo(f"\t\t\t {class_name_OT} \t\t\t")
                click.echo(tabulate(field_data_OT, headers=["Field Name", "Field Value"], tablefmt="fancy_grid"))
                click.echo("")
                
                class_name_TO = self.to_packet.__class__.__name__
                field_data_TO = [(field.name, self.decrease_font_size(str(getattr(self.to_packet, field.name)))) for field in self.to_packet.fields_desc]
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
    

