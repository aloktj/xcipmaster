import click
import sys
import time
import ping3
from scapy import all as scapy_all
import xml.etree.ElementTree as ET
import os
import math
import threading
import pyfiglet
import string
from termcolor import colored
from tabulate import tabulate
import calendar
import logging
import subprocess
import platform
import ipaddress
from datetime import datetime
from struct import pack, unpack 
import binascii
import operator
import struct
# from thirdparty.scapy_cip_enip.plc import PLCClient as client
from thirdparty.scapy_cip_enip.tgv2020 import Client


# Create log directory if it doesn't exist
log_dir = "./log"
os.makedirs(log_dir, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='./log/app.log'
)

ENABLE_NETWORK = True
DEBUG_CIP_FRAMES=bool(False)

class CLI:
    lock = threading.Lock()
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.ip_address = None
        self.cip_xml_path = None
        self.net_test_flag = False
        self.TO_packet = scapy_all.packet
        self.OT_packet = scapy_all.packet
        self.root = None
        self.config_file_names = []
        self.cip_config_attempts = 0
        self.cip_config_selected = None
        self.overall_cip_valid = False
        self.cip_file_count = 0
        self.last_cip_file_name = None
        self.stop_event = None
        self.stop_events = {}
        self.stop_comm_events = None
        self.thread_dict = {}  # Dictionary to store wave threads
        self.cip_test_flag = True
        self.logger.info("Initializing LoggedClass")
        self.can_read_xml_flag = False
        self.platform_multicast_route = None
        self.multicast_route_exist = False
        self.multicast_test_status = False
        self.user_multicast_address = None
        self.time_zone = self.get_system_timezone()
        self.MPU_CTCMSAlive = int(0)
        
        self.CIP_AppCounter = 65500
        self.bCIPErrorOccured = bool(False)
        self.clMPU_CIP_Server = None
        self.pkgCIP_IO = None
        self.TO_packet_class = None
        self.OT_packet_class = None
        self.xml = None
        self.ot_eo_assemblies = None
        self.to_assemblies = None
        
        self.enable_auto_reconnect = bool(False) #Positive Logic : True to enable auto connect; Default disabled
        
    
    ###-------------------------------------------------------------###
    ###                     Header                                  ###
    ###-------------------------------------------------------------###
    
    def spinning_cursor(self):
        while True:
            for cursor in '|/-\\':
                yield cursor
    
    def loading_message(self, message, duration):
        spinner = self.spinning_cursor()
        sys.stdout.write(message)
        sys.stdout.flush()
        start_time = time.time()
        while time.time() - start_time < duration:
            sys.stdout.write(next(spinner))
            sys.stdout.flush()
            time.sleep(0.1)
            sys.stdout.write('\b')
        sys.stdout.write('\r')  # Move cursor to the beginning of the line
        sys.stdout.write(' ' * len(message))  # Clear the loading message
        sys.stdout.write('\r')  # Move cursor to the beginning of the line
        sys.stdout.flush()
        
    def progress_bar(self, message, duration):
        click.echo("\n")
        total_ticks = 75  # Number of ticks in the progress bar
        start_time = time.time()
        while time.time() - start_time < duration:
            elapsed_time = time.time() - start_time
            progress = min(int((elapsed_time / duration) * total_ticks), total_ticks)
            remaining = total_ticks - progress
            bar = '[' + '=' * progress + ' ' * remaining + ']'
            sys.stdout.write('\r')
            sys.stdout.write(f'{message} {bar} {elapsed_time:.1f}s/{duration:.1f}s')
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write('\n')
        click.echo("\n")
    
    
    def display_banner(self):
        table_width = 75
        
        click.echo("\n\n")
        banner_text = pyfiglet.figlet_format("\t\t\t\t\t CIP Tool \t\t\t\t\t", font="slant")
        colored_banner = colored(banner_text, color="green")
        
        banner_table = [[colored_banner]]
        click.echo(tabulate(banner_table, tablefmt="plain"))
        
        # Additional information
        print(*"=" * 100, sep="")
        print(("Welcome to CIP Tool").center(table_width))
        print(("Version: 3.0").center(table_width))
        print(("Author: Alok T J").center(table_width))
        print(("Copyright (c) 2024 Wabtec (based on plc.py)").center(table_width))
        print(*"=" * 100, sep="")
    
    ###-------------------------------------------------------------###
    ###                     Multicast Route                         ###
    ###-------------------------------------------------------------###
    
    def get_multicast_route(self):
        try:
            # Determine the operating system
            os_name = platform.system()
    
            # Execute the appropriate command based on the operating system
            if os_name == 'Windows':
                result = subprocess.run(['route', 'print'], capture_output=True, text=True, check=True)
            elif os_name in ['Linux', 'Darwin']:
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True, check=True)
            else:
                print("Unsupported operating system:", os_name)
                return None
    
            # Split the output into lines
            output_lines = result.stdout.split('\n')
    
            # Find the multicast route
            for line in output_lines:
                if '224.0.0.0/4' in line:
                    self.multicast_route_exist = True
                    return '224.0.0.0/4'
    
            return None
        except subprocess.CalledProcessError:
            # Handle errors if the command fails
            print(f"Error: Unable to execute command on {os_name}.")
            return None
    
    def check_multicast_support(self):
        try:
            # Prompt user for multicast IP address
            
            # Convert user provided IP to IPv4Address object
            user_ip = ipaddress.IPv4Address(self.user_multicast_address)
            print(f"check_multicast_support:{user_ip}")

            self.platform_multicast_route = self.get_multicast_route()
            
            # Convert platform multicast route to IPv4Network object
            if self.multicast_route_exist:
                print("Multicast route exists")
                platform_route = ipaddress.IPv4Network(self.platform_multicast_route)
        
                # Check if user provided IP falls within the platform's multicast route
                print(f"User IP : {user_ip}")
                print(f"Platform_route: {platform_route}")
                if user_ip in platform_route:
                    self.multicast_test_status = True
                    return True
                else:
                    self.multicast_test_status = False
                    return False
            else:
                self.multicast_test_status = False
                return False
        except ipaddress.AddressValueError as e:
            print(f"Exception: {e}")
            print("Invalid multicast group joining IP address.")
            self.multicast_test_status = False
            return False

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
                field_desc.append(scapy_all.StrFixedLenField(field_id, '', int(field_length)))

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
    
    
    def list_files_in_config_folder(self):
        config_folder = "./conf/"
        if not os.path.exists(config_folder) or not os.path.isdir(config_folder):
            click.echo("Config folder does not exist or is not a directory!")
            return
        
        self.config_file_names = os.listdir(config_folder)
        if not self.config_file_names:
            click.echo("No files found in the config folder")
            return
        
        click.echo("Detected Files in Config Folder:")
        click.echo("")
        
        for idx, file in enumerate(self.config_file_names, start=1):
            click.echo(f" {idx}. {file}")
            self.last_cip_file_name = file
            self.cip_file_count += 1
        
        click.echo("")
    
    def cip_config(self):
        self.logger.info("Executing cip_config function")
        
        click.echo("╔══════════════════════════════════════════╗")
        click.echo("║          CIP Configuration               ║")
        click.echo("╚══════════════════════════════════════════╝")
        self.list_files_in_config_folder()
        time.sleep(0.1)
        
        if self.cip_file_count > 1:
            if self.cip_config_attempts == 0:
                self.cip_config_selected = click.prompt("CIP Configuration Filename")
                click.echo("")
            elif self.cip_config_attempts > 0:
                if click.confirm('Do you want to change CIP Configuration?', default=True):
                    self.cip_config_selected = click.prompt("CIP Configuration Filename")
        else:
            self.cip_config_selected = self.last_cip_file_name
            
        # Increment the CIP Configuration Attempt Number
        self.cip_config_attempts += 1
        
        click.echo("\n===== Testing CIP Configuration =====")
        
        test_cases = [
            ("CIP XML Validity", self.check_cip_xml_validity) #,
            # ("Network Connectivity", self.check_network_connectivity),
            # ("Database Connection", self.check_database_connection),
            # Add more test cases as needed
        ]
        
        if self.overall_cip_valid:
            self.cip_test_flag = True
        else:
            self.cip_test_flag = False
        
        results = []
        for test_case, test_function in test_cases:
            result = "OK" if test_function() else "FAILED"
            results.append([test_case, result])
    
        if all(result == "OK" for _, result in results):
            click.echo("All tests passed successfully.")
            click.echo("")
            self.cip_test_flag = True
            return True
        else:
            click.echo("Some tests failed. Restarting CIP Tool.")
            click.echo("")
            return False

    def check_cip_config(self):
        self.logger.info("Executing check_cip_config function")
        """
        Placeholder function to check CIP XML validity.
        Replace the implementation with actual logic.
        """
        config_folder = "./conf/"
        results = []
        
        if not os.path.exists(config_folder) or not os.path.isdir(config_folder):
            click.echo("Config folder does not exist or is not a directory!")
            return
        
        xml_files = [file for file in os.listdir(config_folder) if file.endswith(".xml")]
        if not xml_files:
            results = []
            results.append(["Detect XML in Config Folder", "FAILED"])
            click.echo(tabulate(results, headers=["Test Case", "Status"], tablefmt="fancy_grid"))
            return
        else:
            try:
                xml_filepath = os.path.join("./conf", self.cip_config_selected)
                results.append(["Detect XML in Config Folder", "OK"])
            except FileNotFoundError:
                click.echo("Error: The ./conf folder is empty.")
        
        
    
        # Check if the file exists
        file_exists_status = "OK" if os.path.exists(xml_filepath) else "FAILED"
        results.append(["CIP Conf File Exists", file_exists_status])
    
        # Check if the file is an XML file
        is_xml_status = "OK" if self.cip_config_selected.lower().endswith(".xml") else "FAILED"
        results.append(["File is XML", is_xml_status])
    
        # Check if the file is valid and parseable
        xml_parse_status = ""
        if file_exists_status == "OK" and is_xml_status == "OK":
            try:
                tree = ET.parse(xml_filepath)
                root = tree.getroot()
                self.root = root
                xml_parse_status = "OK"
            except ET.ParseError as e:
                xml_parse_status = f"FAILED: {e}"
        else:
            xml_parse_status = "SKIPPED"
        results.append(["Parse XML", xml_parse_status])
    
        # Check if there is only one assembly element with subtype "OT_EO"
        if xml_parse_status == "OK":
            ot_eo_status = "OK" if self.check_ot_eo(root) else "FAILED"
            results.append(["One Assembly with Subtype 'OT_EO'", ot_eo_status])
        
            # Check if there is only one assembly element with subtype "TO"
            to_status = "OK" if self.check_to(root) else "FAILED"
            results.append(["One Assembly with Subtype 'TO'", to_status])
    
        
        # If file does not exist or is not XML, overall status should be failed
        overall_status = all(status == "OK" for _, status in results)
        if overall_status:
            self.overall_cip_valid = True
        else:
            self.overall_cip_valid = False
            
        results.append(["Overall Status", "OK" if overall_status else "FAILED"])
    
        click.echo(tabulate(results, headers=["Test Case", "Status"], tablefmt="fancy_grid"))
        return overall_status

    def check_ot_eo(self, root):
        assemblies = root.findall("./assembly")
        ot_eo_assemblies = [assembly for assembly in assemblies if assembly.get("subtype") == "OT_EO" and len(assembly.findall("*")) >= 1]
        try:
            self.ot_eo_assemblies = ot_eo_assemblies[0]
            self.OT_packet_class, assembly_size = self.create_packet_class(ot_eo_assemblies[0])
            self.OT_packet = self.OT_packet_class()
            print(f"Length of OT Assembly Expected: {assembly_size//8}")
            print(f"Length of OT Assembly Formed: {len(self.OT_packet)}")
            # print(self.OT_packet.fields_desc)
            
        except:
            print("OT_Packet Creation failed")
            self.logger.info(f"{self.check_ot_eo.__name__}: OT Packet Initialization Failure")
        
        return len(ot_eo_assemblies) == 1

    def check_to(self, root):
        assemblies = root.findall("./assembly")
        to_assemblies = [assembly for assembly in assemblies if assembly.get("subtype") == "TO" and len(assembly.findall("*")) >= 1]
        try:
            self.to_assemblies = to_assemblies[0]
            self.TO_packet_class, assembly_size = self.create_packet_class(to_assemblies[0])
            
            self.TO_packet = self.TO_packet_class()
            print(f"Length of OT Assembly Expected: {assembly_size//8}")
            print(f"Length of OT Assembly Formed: {len(self.TO_packet)}")
            # print(self.TO_packet.fields_desc)
        except:
            print("TO_Packet Creation failed")
            self.logger.info(f"{self.check_to.__name__}: TO Packet Initialization Failure")
        return len(to_assemblies) == 1

    def check_cip_xml_validity(self):
        return self.check_cip_config()
        
    def config_network(self):
        self.logger.info("Executing config_network function")
        click.echo("╔══════════════════════════════════════════╗")
        click.echo("║        Network Configuration             ║")
        click.echo("╚══════════════════════════════════════════╝")
        click.echo("")
        
        self.net_test_flag = False
        self.user_multicast_address = None
        
        time.sleep(0.1)
        
        self.ip_address = click.prompt("Enter Target IP Address", default= '10.0.1.1')
        self.user_multicast_address = click.prompt("Enter the multicast group joining IP address", default='239.192.1.3', type=str)
        
        print(f"ip_address: {self.ip_address}")
        print(f"user_multicast_address : {self.user_multicast_address}")
                
        click.echo("\n===== Testing Communication with Target =====")
        # click.echo(f" Attempting to Communicate with {self.ip_address}")
        time.sleep(1)
        
        results = [["Communication Test Result", "Status"]]
        if self.communicate_with_target():
            results.append(["Communication with Target", "OK"])
            # click.echo(" Communication has been Tested -> OK")
        else:
            results.append(["Communication with Target", "FAILED"])
            # click.echo(" Communication has been Tested -> FAILED")
            
            
        if self.check_multicast_support():
            results.append(["Mutlicast Group Join", "OK"])
        else:
            results.append(["Mutlicast Group Join", "FAILED"])
        
        if self.multicast_route_exist:
            results.append(["Mutlicast route Compatibity", "OK"])
        else:
            results.append(["Mutlicast route Compatibity", "FAILED"])
        
        click.echo("\n" + tabulate(results, headers="firstrow", tablefmt="fancy_grid"))
        click.echo("")
            
        
        if self.net_test_flag and self.multicast_test_status:
            time.sleep(0.1)
            return True
        else:
            click.echo("===== Falsed Network Configuration Test =====")
            click.echo("")
            click.echo("=============================================")
            click.echo("=====        Restarting CIP Tool        =====")
            click.echo("=============================================")
            return False
        
    def communicate_with_target(self):
        self.logger.info("Executing communication_with_target function")
        self.net_test_flag = False
        try:
            ###########Testing#############
            DCU_PING_CMD =  f'ping -c 1 {self.ip_address}'
            PingResult = os.system(DCU_PING_CMD)
            print(PingResult)
            if(PingResult!=0):
                self.net_test_flag = False
                return False
            else:
                self.net_test_flag = True
                return True
        except Exception as e:
            click.echo("Error occurred: {}".format(e))
            self.net_test_flag = False
            time.sleep(0.1)
            return False
            
            
    ############ Help Menu ############ 
    def help_menu(self):
        self.logger.info("Executing help_menu function")
        click.echo("\nAvailable commands:")
        
        commands = [
            ("start", "Start Communication"),
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
            ("cip_config", "Restart CIP Config"),
            ("test_net", "Test Network Config"),
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
        
        if hasattr(self.OT_packet,field_name):
            field = getattr(self.OT_packet.__class__, field_name)
            if isinstance(field, scapy_all.ByteField):
                    setattr(self.OT_packet, field_name, field_value)
                    self.logger.info("MPU_HeartBeat set")
            else:
                self.logger.warning("Heartbeat is not ByteField type")
        else:
            self.logger.warning(f"There is no HearBeat with the name: {field_name}")

    
    def set_field(self, field_name, field_value):
        self.logger.info("Executing set_field function")
        self.stop_wave(field_name)
        self.lock.acquire()
        if hasattr(self.OT_packet, field_name):
            field = getattr(self.OT_packet.__class__, field_name)
            if isinstance(field, scapy_all.IEEEFloatField):
                try:
                    byte_array = struct.pack('f', float(field_value))
                    reversed_byte_array = byte_array[::-1]
                    bE_field_value = struct.unpack('f', reversed_byte_array)[0] #Big endian field value
                    setattr(self.OT_packet, field_name, bE_field_value)
                    print(f"Set {field_name} to {field_value}")
                except ValueError:
                    print(f"Field {field_name} expects a float value.")
            elif isinstance(field, scapy_all.BitField):
                if field_value in ['0', '1']:
                    setattr(self.OT_packet, field_name, int(field_value))
                    print(f"Set {field_name} to {field_value}")
                else:
                    print(f"Field {field_name} expects a value of either '0' or '1'.")
            elif isinstance(field, scapy_all.ByteField):
                if field_value.startswith('0x') and len(field_value) == 4 and all(
                        c in string.hexdigits for c in field_value[2:]):
                    int_value = int(field_value, 16)
                    setattr(self.OT_packet, field_name, int_value)
                    print(f"Set {field_name} to {field_value}")
                elif field_value.isdigit():
                    int_value = int(field_value)
                    if 0 <= int_value <= 0xFF:
                        setattr(self.OT_packet, field_name, int_value)
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
                    setattr(self.OT_packet, field_name, int(int_value.to_bytes(2, byteorder='big')))
                    print(f"Set {field_name} to {field_value}")
                elif field_value.isdigit():
                    int_value = int(field_value)
                    if 0 <= int_value <= 0xFFFF:
                        try:
                            byte_array = int_value.to_bytes(2, byteorder='big')
                            reversed_byte_array = byte_array[::-1]
                            converted_value = int.from_bytes(reversed_byte_array, byteorder='big')
                            setattr(self.OT_packet, field_name, converted_value)
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
                    setattr(self.OT_packet, field_name, int_value.to_bytes(2, byteorder='big'))
                    print(f"Set {field_name} to {field_value}")

                elif field_value.isdigit():

                    int_value = int(field_value)
                    if 0 <= int_value <= 0xFFFF:
                        setattr(self.OT_packet, field_name, int_value) 
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

                        setattr(self.OT_packet, field_name, int_value)

                        print(f"Set {field_name} to {field_value}")

                    else:

                        print("Value out of range for IEEEDoubleField")

                elif field_value.isdigit():

                    int_value = float(field_value)

                    if 0 <= int_value <= (2**64 - 1):

                        setattr(self.OT_packet, field_name, int_value)  

                        print(f"Set {field_name} to {field_value}")

                    else:

                        print("Value out of range for IEEEDoubleField")

                else:

                    print("Field value must be a number for IEEEDoubleField")
            
            
            elif isinstance(field, scapy_all.StrFixedLenField):
                if isinstance(field_value, str):
                    
                    field_value1 = field_value
                    field_value = field_value.encode() # Convert String to Bytes
                    print(field_value)
                if not isinstance(field_value, bytes):
                    print(f"Field values is not byte type")
                field_value1 = field_value
                # field_bytes = field_value.rjust(field.length_from(self.OT_packet), b'\x00')
                                
                if len(field_value) <= field.length_from(self.OT_packet):
                    setattr(self.OT_packet, field_name, field_value)
                    print(f"Set {field_name} to {field_value}")
                else:
                    print(f"Field {field_name} expects a string of length up to {field.length_from(self.OT_packet)}.")
            else:
                print(f"Field {field_name} is not of type IEEEFloatField, BitField, ByteField, or StrFixedLenField and "
                      f"cannot be set.")
        else:
            print(f"Field {field_name} not found.")
            
        self.lock.release()
        
       
    def clear_field(self, field_name):
        self.logger.info("Executing clear_field function")
        self.stop_wave(field_name)
        if hasattr(self.OT_packet, field_name):
            field = getattr(self.OT_packet.__class__, field_name)
            if isinstance(field, scapy_all.IEEEFloatField) or isinstance(field, scapy_all.BitField) or isinstance(field, scapy_all.ByteField):
                setattr(self.OT_packet, field_name, 0)
                print(f"Cleared {field_name}")
            elif isinstance(field, scapy_all.StrFixedLenField):
                setattr(self.OT_packet, field_name, '')
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
        
        if hasattr(self.OT_packet, field_name):
            field_value = self.get_big_endian_value(self.OT_packet, field_name)
            packet_type = self.OT_packet.__class__.__name__
            field_data = [(packet_type, field_name, self.decrease_font_size(str(field_value)))]
            
        elif hasattr(self.TO_packet, field_name):
            field_value = self.get_big_endian_value(self.TO_packet, field_name)
            packet_type = self.TO_packet.__class__.__name__
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
        class_name_OT = self.OT_packet.__class__.__name__
        field_data_OT = [(field.name, self.decrease_font_size(str(self.get_big_endian_value(self.OT_packet, field.name)))) for field in self.OT_packet.fields_desc]
        self.lock.release()
        click.echo(f"\t\t\t {class_name_OT} \t\t\t")
        click.echo(tabulate(field_data_OT, headers=["Field Name", "Field Value"], tablefmt="fancy_grid"))
        click.echo("")
        
        self.lock.acquire()
        class_name_TO = self.TO_packet.__class__.__name__
        field_data_TO = [(field.name, self.decrease_font_size(str(self.get_big_endian_value(self.TO_packet, field.name)))) for field in self.TO_packet.fields_desc]
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
        
        self.print_packet_fields(self.OT_packet.__class__.__name__ , self.OT_packet)
        
        self.print_packet_fields(self.TO_packet.__class__.__name__ , self.TO_packet)
        
    
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
                
                class_name_OT = self.OT_packet.__class__.__name__
                field_data_OT = [(field.name, self.decrease_font_size(str(getattr(self.OT_packet, field.name)))) for field in self.OT_packet.fields_desc]
                click.echo(f"\t\t\t {class_name_OT} \t\t\t")
                click.echo(tabulate(field_data_OT, headers=["Field Name", "Field Value"], tablefmt="fancy_grid"))
                click.echo("")
                
                class_name_TO = self.TO_packet.__class__.__name__
                field_data_TO = [(field.name, self.decrease_font_size(str(getattr(self.TO_packet, field.name)))) for field in self.TO_packet.fields_desc]
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
    
    def wave_field(self, field_name, max_value, min_value, period_ms):
        self.logger.info("Executing wave_field function")
        self.stop_wave(field_name)
        field = getattr(self.OT_packet.__class__, field_name)
        if isinstance(field, scapy_all.IEEEFloatField):
            max_value = float(max_value)
            min_value = float(min_value)
            period_ms = float(period_ms) / 1000  # Convert milliseconds to seconds
            amplitude = (max_value - min_value) / 2
            offset = (max_value + min_value) / 2

            def wave_thread():
                self.logger.info("Executing wave_thread function")
                start_time = time.time()
                while not self.stop_events[field_name].is_set():
                    current_time = time.time()
                    elapsed_time = current_time - start_time
                    wave_value = amplitude * math.sin(2 * math.pi * elapsed_time / period_ms) + offset
                    
                    byte_array = struct.pack('f', float(wave_value))
                    reversed_byte_array = byte_array[::-1]
                    bE_field_value = struct.unpack('f', reversed_byte_array)[0] #Big endian field value
                    setattr(self.OT_packet, field_name, bE_field_value)
                    
                    # print(f"Set {field_name} to {wave_value}")
                    time.sleep(0.01)  # Adjust sleep time as needed

            self.stop_events[field_name] = threading.Event()
            wave_thread_instance = threading.Thread(target=wave_thread)
            wave_thread_instance.start()
            print(f"Waving {field_name} from {min_value} to {max_value} every {period_ms} milliseconds.")
        else:
            print(f"Field {field_name} is not of type IEEEFloatField and cannot be waved.")
            
    def tria_field(self, field_name, max_value, min_value, period_ms):
        self.logger.info("Executing tria_field function")
        self.stop_wave(field_name)
        field = getattr(self.OT_packet.__class__, field_name)
        if isinstance(field, scapy_all.IEEEFloatField):
            max_value = float(max_value)
            min_value = float(min_value)
            period_ms = float(period_ms) / 1000  # Convert milliseconds to seconds
            amplitude = (max_value - min_value) / 2
            offset = (max_value + min_value) / 2

            def tria_wave_thread():
                self.logger.info("Executing tria_wave_thread function")
                start_time = time.time()
                while not self.stop_events[field_name].is_set():
                    current_time = time.time()
                    elapsed_time = current_time - start_time
                    phase = elapsed_time / period_ms
                    wave_value = (amplitude * (2 * abs(phase - math.floor(phase + 0.5)) - 1)) + offset
                    byte_array = struct.pack('f', float(wave_value))
                    reversed_byte_array = byte_array[::-1]
                    bE_field_value = struct.unpack('f', reversed_byte_array)[0] #Big endian field value
                    setattr(self.OT_packet, field_name, bE_field_value)
                    # print(f"Set {field_name} to {wave_value}")
                    time.sleep(0.01)  # Adjust sleep time as needed

            self.stop_events[field_name] = threading.Event()
            wave_thread_instance = threading.Thread(target=tria_wave_thread)
            wave_thread_instance.start()
            print(f"Triangular waving {field_name} from {min_value} to {max_value} every {period_ms} milliseconds.")
        else:
            print(f"Field {field_name} is not of type IEEEFloatField and cannot be waved.")
            
    
    def box_field(self, field_name, max_value, min_value, period_ms, duty_cycle):
        self.logger.info("Executing box_field function")
        self.stop_wave(field_name)
        field = getattr(self.OT_packet.__class__, field_name)
        if isinstance(field, scapy_all.IEEEFloatField):
            max_value = float(max_value)
            min_value = float(min_value)
            period_ms = float(period_ms) / 1000  # Convert milliseconds to seconds
            duty_cycle = float(duty_cycle)
            # amplitude = (max_value - min_value) / 2
            # offset = (max_value + min_value) / 2

            def box_wave_thread():
                self.logger.info("Executing box_wave_thread function")
                start_time = time.time()
                while not self.stop_events[field_name].is_set():
                    current_time = time.time()
                    elapsed_time = current_time - start_time
                    duty_period = period_ms * duty_cycle
                    wave_value = max_value if (elapsed_time % period_ms) < duty_period else min_value
                    byte_array = struct.pack('f', float(wave_value))
                    reversed_byte_array = byte_array[::-1]
                    bE_field_value = struct.unpack('f', reversed_byte_array)[0] #Big endian field value
                    setattr(self.OT_packet, field_name, bE_field_value)
                    # print(f"Set {field_name} to {wave_value}")
                    time.sleep(0.01)  # Adjust sleep time as needed

            self.stop_events[field_name] = threading.Event()
            wave_thread_instance = threading.Thread(target=box_wave_thread)
            wave_thread_instance.start()
            print(f"Generating square wave for {field_name} with duty cycle {duty_cycle} every {period_ms} milliseconds.")
        else:
            print(f"Field {field_name} is not of type IEEEFloatField and cannot be waved.")
            
    def stop_all_thread(self):
        self.logger.info(f"{self.stop_all_thread.__name__}: Stopping all wave threads for domain")
        for field_name in self.stop_events:
            self.stop_events[field_name].set()
            click.echo(f"{self.stop_all_thread.__name__}: Waving for '{field_name}' has been stopped")
        self.logger.info(f"{self.stop_all_thread.__name__}: All wave threads have been successfully stopped")

            
    def stop_wave(self, field_name):
        self.logger.info("Executing stop_wave function")
        if field_name in self.stop_events and not self.stop_events[field_name].is_set():
            self.stop_events[field_name].set()
            click.echo(f"\nWaving for '{field_name}' has been stopped.\n")
            
    def print_last_logs(self):
        log_file_path = "./log/app.log"
        if os.path.exists(log_file_path):
            with open(log_file_path, "r") as log_file:
                lines = log_file.readlines()
                last_100_lines = lines[-100:]
                click.echo("Last 100 lines of app.log:")
                for line in last_100_lines:
                    click.echo(line.strip())
    
    def calculate_connection_params(self):
        ot_size = None
        to_size = None
                
        try:
            ot_size = int(self.ot_eo_assemblies.attrib.get("size"))
            to_size = int(self.to_assemblies.attrib.get("size"))
        except:
            self.logger.info("Unable to fetch assembly size")
        
        # Calculate OT_Connection_param and TO_Connection_param
        if ot_size is not None:
            ot_connection_param = 0x4800 | ((ot_size // 8) + 6)
        else:
            ot_connection_param = None
        if to_size is not None:
            to_connection_parma = 0x2800 | ((to_size // 8) + 6)
        else:
            to_connection_parma = None
        
        return (ot_connection_param,to_connection_parma)
    
    def ManageCIP_IOCommunication(self, clMPU_CIP_Server):
        self.logger.info("Executing ManageCIP_IOCommunication function")
        
        #alive byte used by DCU to check MPU activity
        MPU_CTCMSAlive = int(0)
        
        CIP_AppCounter = 65500
        bCIPErrorOccured = bool(False)
        
        #infinite loop to manage CIP IO DCU<->MPU until CIP error occured
        while(not(bCIPErrorOccured)):
            
            pkgCIP_IO = clMPU_CIP_Server.recv_UDP_ENIP_CIP_IO(DEBUG_CIP_FRAMES,0.5)
            
            if(pkgCIP_IO != None):
                self.logger.info("ManageCIP_IOCommunication: pkgCIP_IO - Detected Incoming Stream")
                
                # Parse the TO Packet from CIP IO Payload
                self.lock.acquire()
                self.TO_packet = self.TO_packet_class((pkgCIP_IO.payload.load))
                
                # self.TO_packet.show()
                self.lock.release()
                
                self.lock.acquire()  
                if(self.TO_packet != None):
                    self.logger.info("ManageCIP_IOCommunication: TO_packet data parsed successfuly")
                    if(MPU_CTCMSAlive>=255):
                        MPU_CTCMSAlive = 0
                    else:
                        MPU_CTCMSAlive += 1 ##1 step per 100 ms = 1 step per 100 ms see ICD
                        
                    
                    self.MPU_heartbeat('MPU_CTCMSAlive',MPU_CTCMSAlive)
                    
                    self.OT_packet.MPU_CDateTimeSec = calendar.timegm(time.gmtime())
                    clMPU_CIP_Server.send_UDP_ENIP_CIP_IO(CIP_Sequence_Count=CIP_AppCounter, Header=1,AppData=self.OT_packet)
                    
                    #CIP_Sequence_Count must be from 0 to 65535
                    if(CIP_AppCounter < 65535):
                        CIP_AppCounter += 1
                    else:
                        CIP_AppCounter = 0
                else:
                    self.logger.warning("ManageCIP_IOCommunication: TO_packet data parse failed")
                    bCIPErrorOccured = True
                
                self.lock.release()
                    
            else:
                self.logger.warning("Not possible to convert CIP IO frame into scapy packet class")
                bCIPErrorOccured = True
                return(bCIPErrorOccured)
        
        # end while
        return(bCIPErrorOccured)
       
    def start_comm(self):
        self.logger.info("Executing CIP Communication Start function")

        if self.enable_auto_reconnect:
            self.logger.warning("Auto-Reconnect Detected")
        else:
            self.logger.warning("Manual Connect Detected")
            
        ot_param,to_param = self.calculate_connection_params()
        self.logger.info(f"ot_param:{hex(ot_param)}")
        self.logger.info(f"to_param:{hex(to_param)}")
        
        if ot_param != None:
            self.logger.warning("start_comm: ot_connection_param is defined")
        else:
            self.logger.warning("start_comm: ot_connection_param is None")
            return
        if to_param != None:
            self.logger.warning("start_comm: ot_connection_param is defined")
        else:
            self.logger.warning("start_comm: to_connection_param is None")
            return
        
        def start_comm_thread():            
            while self.enable_auto_reconnect or not self.stop_comm_events.is_set():
                try:
                    self.logger.info("Executing start_comm_thread function")
                    self.clMPU_CIP_Server = Client(IPAddr=self.ip_address,MulticastGroupIPaddr=self.user_multicast_address)
                    self.clMPU_CIP_Server.ot_connection_param = ot_param
                    self.clMPU_CIP_Server.to_connection_param = to_param
                    
                    self.logger.info("Done Printing Param")
                    
                    if(self.clMPU_CIP_Server.connected):
                        self.logger.info(f"start_comm_thread: Established Session{format(self.clMPU_CIP_Server.connected)}")
                        
                        # Send forward open and wait DCU response
                        bForwoardOpenRspIsOK = self.clMPU_CIP_Server.forward_open()
                        if(bForwoardOpenRspIsOK):
                            self.logger.info("start_comm_thread: Forward Open OK")
                        else:
                            self.logger.warning("start_comm_thread: Forward Open request failed")
                            raise ConnectionError("Forward Open request failed")
                        
                        # Manage CIP IO cyclic communication
                        self.bCIPErrorOccured = self.ManageCIP_IOCommunication(self.clMPU_CIP_Server)
                        
                        if(not(self.bCIPErrorOccured)):
                            # Close CIP connection
                            self.clMPU_CIP_Server.forward_close() 
                            
                        #Close all sockets
                        self.clMPU_CIP_Server.close()
                        
                        if not self.enable_auto_reconnect:
                            self.logger.info("start_comm_thread: Auto Reconnect is disabled & thread is exiting")
                            break
                
                    #no connected                    
                    else:
                        self.logger.warning("start_comm_thread: Not able to establish session")
                        raise ConnectionError("Failed to establish session")
                        
                except (ConnectionError, Exception) as e:
                    self.logger.error(f"Connection error: {str(e)}")
                    if self.enable_auto_reconnect:
                        self.logger.info("Auto-reconnect is enabled. Retrying in 2 seconds...")
                        time.sleep(2)
                    else:
                        self.logger.info("Auto-reconnect is disabled. Exiting communication thread.")
                        break
                    
                if self.stop_comm_events.is_set():
                    break
                
                if self.enable_auto_reconnect:
                    time.sleep(2)
                else:
                    break
            
            self.logger.info("start_comm_thread: Thread has finished execution")
        
                
        self.stop_comm_events = threading.Event()
        start_comm_thread_instance = threading.Thread(target=start_comm_thread)
        start_comm_thread_instance.start()
        
    def enable_auto_com(self):
        self.logger.info(f"{self.enable_auto_com.__name__}: Automatic Communication enabled")
        self.enable_auto_reconnect = True
    
    def disable_auto_com(self):
        self.logger.info(f"{self.disable_auto_com.__name__}: Automatic Communication disabled")
        self.enable_auto_reconnect = False
        self.stop_comm()  # Stop communication when disabling auto mode
        
        
    def stop_comm(self):
        self.logger.info(f"{self.stop_comm.__name__}: Stopping comm thread")
        self.stop_comm_events.set() # Set the event to stop the thread
        
        try:
            if hasattr(self, 'clMPU_CIP_Server') and self.clMPU_CIP_Server is not None:
                if(not(self.bCIPErrorOccured)):
                    # Close CIP connection
                    try:
                        self.clMPU_CIP_Server.forward_close()
                        self.logger.info(f"{self.stop_comm.__name__}: Stopping comm thread")
                    except Exception as e:
                        self.logger.error(f"{self.stop_comm.__name__}: Error closing CIP connection: {str(e)}")
                        click.echo(f"Error closing CIP connection: {str(e)}")
                try:    
                    self.clMPU_CIP_Server.close()
                    self.logger.info(f"{self.stop_comm.__name__}: Server connection closed successfully")
                except Exception as e:
                    self.logger.error(f"{self.stop_comm.__name__}: Error closing server connection: {str(e)}")
                    click.echo(f"Error closing server connection: {str(e)}")
    
            if hasattr(self, 'start_comm_thread_instance') and self.start_comm_thread_instance.is_alive():
                self.start_comm_thread_instance.join(timeout=5) # Wait up to 5 seconds for the thread to finish
                
                if self.start_comm_thread_instance.is_alive():
                    self.logger.warning(f"{self.stop_comm.__name__}: Thread did not stop within the timeout period")
                    click.echo("Warning: Communication thread did not stop within the expected time")
                else:
                    self.logger.info(f"{self.stop_comm.__name__}: Thread stopped successfully")
        
            self.logger.info(f"{self.stop_comm.__name__}: Comm Thread has been successfully stopped")
            
        except Exception as e:
            self.logger.error(f"{self.stop_comm.__name__}: Unexpected error while stopping communication: {str(e)}")
            click.echo(f"Unexpected error while stopping communication: {str(e)}")
        finally:
            if hasattr(self, 'start_comm_thread_instance') and self.start_comm_thread_instance.is_alive():
                click.echo("Warning: Communication thread is still running")
            else:
                click.echo("Communication thread has been successfully stopped")
    
    def handle_input(self):
        self.logger.info("Executing handle_input function")
        self.help_menu()
        
        try:
            while True:
                    print("")
                    command = click.prompt("Enter Command").strip().split()
                    if command[0] == "start" and len(command) == 1:
                        if self.enable_auto_reconnect:
                            click.echo("Disabled auto-Connect using the CMD: <man> and try again !!!")
                        else:
                            click.echo("Attempting to Start communication...")
                            self.start_comm()
                    elif command[0] == "stop" and len(command) == 1:
                        if self.enable_auto_reconnect:
                            click.echo("Disabled auto-Connect using the CMD: <man> and try again !!!")
                        else:
                            click.echo("Attempting to Stop communication...")
                            self.stop_comm()
                    elif command[0] == "auto" and len(command) == 1:
                        if self.enable_auto_reconnect:
                            click.echo("Already in auto-reconnect mode.")
                        else:
                            click.echo("Switching to Auto-Reconnect Mode!")
                            self.enable_auto_com()
                            self.start_comm()
                    elif command[0] == "man" and len(command) == 1:
                        if self.enable_auto_reconnect:
                            click.echo("Switching to Manual Connect Mode!")
                            self.disable_auto_com()
                            time.sleep(2)
                        else:
                            click.echo("Already in manual mode")
                    elif command[0] == "set" and len(command) == 3:
                        self.set_field(command[1], command[2])
                    elif command[0] == "clear" and len(command) == 2:
                        self.clear_field(command[1])
                    elif command[0] == "get" and len(command) == 2:
                        self.get_field(command[1])
                    elif command[0] == "frame" and len(command) == 1:
                        self.print_frame()
                    elif command[0] == "fields" and len(command) == 1:
                        self.list_fields()
                    elif command[0] == "wave" and len(command) == 5:
                        self.wave_field(command[1], float(command[2]), float(command[3]), int(command[4]))
                    elif command[0] == "tria" and len(command) == 5:
                        self.tria_field(command[1], float(command[2]), float(command[3]), int(command[4]))
                    elif command[0] == "box" and len(command) == 6:
                        self.box_field(command[1], float(command[2]), float(command[3]), int(command[4]), float(command[5]))
                    elif command[0] == "live" and len(command) == 2:
                        self.live_field_data(command[1])
                    elif command[0] == "stop_wave" and len(command) == 2:
                        self.stop_wave(command[1])
                    elif command[0] == "cip_config" and len(command) == 1:
                        while False == self.cip_config() :
                            self.cip_config()
                    elif command[0] == "test_net" and len(command) == 1:
                        while False == self.config_network() :
                            self.config_network()
                    elif command[0] == "log" and len(command) == 1:
                        self.print_last_logs()
                    elif command[0] == "help":
                        self.help_menu()
                    elif command[0] == "exit":
                        click.echo("Exiting !")
                        self.stop_all_thread()
                        sys.exit()
                    else:
                        click.echo("Invalid cmd")
            
        except KeyboardInterrupt:
            click.echo("Exiting !!")
            self.stop_all_thread()
            sys.exit()
                
            
def main():
    
    global ENABLE_NETWORK
    cmd = CLI()
    cmd.display_banner()
    
    cmd.progress_bar("Initializing", 1)

    if cmd.cip_test_flag:
        if click.confirm('Do you want to continue?', default=True):
            # If user answers yes
            cmd.cip_config()
        else:
            # If user answers no
            click.echo('Exiting...')
            sys.exit()
        
    # Test CIP Configuration
    if not cmd.cip_test_flag:
        main() # Restart configuration if failed

    # Test Target Communication
    if ENABLE_NETWORK:
        if not cmd.config_network():
            main()  # Restart configuration if failed

    # Handle the Input from User in a loop
    cmd.handle_input()

if __name__ == "__main__":
    main()
