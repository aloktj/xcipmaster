"""Core controller for the CIP command-line interface."""

import logging
import operator
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
        return self.config_service.OT_packet

    @ot_packet.setter
    def ot_packet(self, value):
        self.config_service.OT_packet = value

    @property
    def to_packet(self):
        return self.config_service.TO_packet

    @to_packet.setter
    def to_packet(self, value):
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
 
    # Dynamically create a Scapy packet class
    def create_packet_dict(self, fields_dict, assembly_size):
        max_packet_size_bits= assembly_size
        self.logger.info("Create_Packet_Dictionary()")
        print(f"Assembly Size: {max_packet_size_bits}")
        fields_desc = []
        pack_bools = {}
        signals = {}
        
        cip_data_type_size = {
            'usint': 1,
            'uint': 2,
            'udint': 4,
            'real': 4,
            'string': 1,
            'sint': 1,
            'int': 2,
            'dint': 4,
            'lreal': 8,
            'lint': 8
            
            # Add more datatypes if needed (except bool) (Size in Bytes)
        }
        
        print("")
        print("Create Packet Dict Called")
        # Sort fields by their offsets to ensure correct packing
        fields_dict.sort(key=operator.itemgetter('offset'))
        # print("SORTED FIELD")
        # for field in fields_dict:
        #     print(f"ID: {field['id']}, Offset: {field['offset']}, Type: {field['type']}")
            
        self.logger.info("create_packet_dict: Sorted Fields")

        sorted_dict = {}
        # for item in fields_dict:
        #     sorted_dict[item["id"]] = {"offset": item["offset"], 
        #                             "type": item["type"], 
        #                             "length": item["length"]}    
        for item in fields_dict:
            sorted_dict[item["id"]] = {"offset": item["offset"], 
                                    "type": item["type"], "length": item["length"]}   
        
        # Iterate through sorted fields to organize signals into byte-sized packages
        for field_id, field_info in sorted_dict.items():
            offset = field_info['offset']
            field_type = field_info['type']
            field_length = field_info['length']

            # Calculate byte index for the current offset
            byte_index = offset // 8

            # Create a new package for the byte if it doesn't exist
            if byte_index not in signals:
                signals[byte_index] = []

            # Append the signal to the corresponding package
            if field_type == "bool":
                signals[byte_index].append({'id': field_id, 'offset': offset, 'type': "bool", 'length': 1})

        # Iterate through byte-sized packages to add signals and spares to the field description
        len_counter = 0
        temp_pad_index = 0
        temp_pad_len = 0
        for byte_index in range(( max_packet_size_bits // 8)):
            
            if len_counter != 0:
                len_counter -= 1
                continue
            
            pack = signals.get(byte_index, [])
            if not pack:  # If no signals in this byte range
                signals[byte_index] = []
                # Check if there are other field types present in this byte range
                for field_id, field_info in sorted_dict.items():
                    if field_info['offset'] == byte_index * 8 and field_info['type'] != 'bool':
                        field_data = (field_id, field_info['type'], field_info['length'])
                        break
                    else:
                        field_data = None

                if field_data:
                    if temp_pad_len > 0:
                        signals[temp_pad_index].append(
                            {'id': f"spare_byte_{temp_pad_index}", 'offset': temp_pad_index * 8, 'type': "string", 'length': temp_pad_len})
                        temp_pad_len = 0
                        temp_pad_index = 0
                    
                    field_name, field_type, field_length = field_data
                    signals[byte_index].append({'id': field_name, 'offset': byte_index * 8,  
                                                'type': field_type, 'length': field_length})
                    len_counter_field_size = cip_data_type_size.get(field_type, 1)
                    
                    len_counter = field_length*len_counter_field_size  - 1      # Support only String, TODO: make it support all datatype except bool
                else:
                    len_counter = 0
                    if temp_pad_len == 0:
                        temp_pad_index = byte_index
                    temp_pad_len += 1

            else:
                if temp_pad_len > 0:
                    signals[temp_pad_index].append(
                        {'id': f"spare_byte_{temp_pad_index}", 'offset': temp_pad_index * 8, 'type': "string", 'length': temp_pad_len})
                    temp_pad_len = 0
                    temp_pad_index = 0
                    
                occupied_offsets = {signal['offset'] % 8 for signal in pack}
                for bit_index in range(8):
                    if bit_index not in occupied_offsets:
                        bit_offset = byte_index * 8 + bit_index
                        signals[byte_index].append(
                            {'id': f"spare_bit_{byte_index}_{bit_index}", 'offset': bit_offset, 'type': "bool", 'length': 1})
                signals[byte_index].sort(key=lambda x: x['offset'])
        
        if temp_pad_len > 0:
            signals[temp_pad_index].append({'id': f"spare_byte_{temp_pad_index}", 'offset': temp_pad_index * 8, 'type': "string", 'length': temp_pad_len})

        return signals
    
    def sorted_fields(self, packet):
        self.logger.info("sorted_fields()")
        fields = []
        for byte_index, signals in packet.items():
            for signal in signals:
                fields.append({'id': signal['id'], 'offset': signal['offset'], 'type': signal['type'], 'length': signal['length']})

            # Sort fields based on offset value
            fields = sorted(fields, key=lambda x: x['offset'])
        return fields

    
    def create_packet_class(self, assembly_element):
        self.logger.info("create_packet_class()")
        subtype = assembly_element.attrib['subtype']
        assembly_size = int(assembly_element.attrib['size'])
        if subtype not in ['OT_EO', 'TO']:
            return None  # Skip creation if subtype is not 'OT_EO' or 'TO'

        class_name = assembly_element.attrib['id']
        fields_dict = []

        for field in assembly_element.findall('.//'):
            field_len = int(field.attrib.get('length', 1))
            fields_dict.append({'id': field.attrib['id'], 'offset': int(field.attrib['offset']), 'type': field.tag, 'length': field_len})

        byte_packet_field = self.create_packet_dict(fields_dict, assembly_size)
        sorted_field = self.sorted_fields(byte_packet_field)
        field_desc = []

        for field in sorted_field:
            field_id = field['id']
            field_type = field['type']
            field_length = field['length']
            field_offset = field['offset']

            if field_type == "usint":
                field_desc.append(scapy_all.ByteField(field_id, 0))

            elif field_type == "bool":
                field_desc.append(scapy_all.BitField(field_id, 0, 1))

            elif field_type == "real":
                field_desc.append(scapy_all.IEEEFloatField(field_id, 0))

            elif field_type == "string":
                field_desc.append(scapy_all.StrFixedLenField(field_id, b'', int(field_length)))

            elif field_type == "udint":
                field_desc.append(scapy_all.LEIntField(field_id, 0))

            elif field_type == "uint":
                field_desc.append(scapy_all.ShortField(field_id, 0))
            elif field_type == "sint":
                field_desc.append(scapy_all.SignedByteField(field_id, 0))

        dynamic_packet_class = type(class_name, (scapy_all.Packet,), {'name': class_name, 'fields_desc': field_desc})
        return dynamic_packet_class, assembly_size
    
              
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
    
    
    def print_packet_fields(self, title, packet, show_spares=False):
        # Organizing fields by type for the given packet
        fields_by_type = {}
        for field in packet.fields_desc:
            field_type = type(field).__name__
            if field_type not in fields_by_type:
                fields_by_type[field_type] = []
            fields_by_type[field_type].append(field.name)

        packet_table = []
        for field_type, field_names in fields_by_type.items():
            field_str = ", ".join(field_names)
            if len(field_str) > 100:
                # Split field names into chunks without cutting them
                field_str = ""
                curr_len = 0
                for name in field_names:
                    if curr_len + len(name) + 2 > 100:  # Check if adding the next field name exceeds 100 characters
                        field_str += "\n" + name + ", "  # Add newline and comma if needed
                        curr_len = len(name) + 2  # Update current length
                    else:
                        field_str += name + ", "  # Add field name and comma
                        curr_len += len(name) + 2  # Update current length
                field_str = field_str.rstrip(", ")  # Remove trailing comma and space

            packet_table.append([field_type, field_str])

        # If show_spares is False, remove spare fields from packet_table
        if not show_spares:
            packet_table = [row for row in packet_table if not row[0].startswith("Spare_")]

        # Calculate the width of the table
        table_width = 100

        # Print the table with a title header centered above the table
        headers = ["Field Type", "Field Names"]
        colalign = ["left", "left"]  # Setting alignment for both columns to left
        title_header = f"{title}:"
        click.echo(title_header.center(table_width))
        click.echo(tabulate(packet_table, headers=headers, colalign=colalign, tablefmt="fancy_grid"))
        click.echo("")
        
    def list_fields(self):
        self.logger.info("Executing list_fields function")
        
        self.print_packet_fields(self.ot_packet.__class__.__name__ , self.ot_packet)
        
        self.print_packet_fields(self.to_packet.__class__.__name__ , self.to_packet)
        
    
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
    

