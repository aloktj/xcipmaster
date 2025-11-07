"""Configuration and packet management services for XCIP Master."""
from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple, Type

from scapy import all as scapy_all


@dataclass
class PacketLayout:
    """Description of a dynamically generated packet class."""

    name: str
    subtype: str
    assembly_size: int
    packet_class: Type[scapy_all.Packet]
    byte_map: Dict[int, List[dict]]
    fields: List[dict]


@dataclass
class CIPConfigResult:
    """Result of executing configuration validation."""

    resolved_path: Optional[Path]
    tests: List[Tuple[str, str]] = field(default_factory=list)
    success: bool = False


class CIPConfigService:
    """Service responsible for loading and validating CIP configurations."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.cip_xml_path: Optional[Path] = None
        self.cip_config_selected: Optional[str] = None
        self.overall_cip_valid: bool = False
        self.cip_test_flag: bool = True
        self.can_read_xml_flag: bool = False
        self.root: Optional[ET.Element] = None
        self.ot_eo_assemblies = None
        self.to_assemblies = None
        self.OT_packet_class = None
        self.TO_packet_class = None
        self.OT_packet = None
        self.TO_packet = None
        self._packet_layouts: Dict[str, PacketLayout] = {}
        self._packet_instances: Dict[str, scapy_all.Packet] = {}

    def list_files_in_config_folder(self, config_folder: str) -> Sequence[Path]:
        """Return a sorted list of XML files in *config_folder*."""

        folder_path = Path(config_folder).expanduser()
        self.logger.debug("Listing XML files from %s", folder_path)

        if not folder_path.exists() or not folder_path.is_dir():
            self.logger.warning("Config folder does not exist or is not a directory: %s", folder_path)
            return []

        xml_files = sorted(
            [path for path in folder_path.iterdir() if path.suffix.lower() == ".xml"]
        )
        return xml_files

    def resolve_cip_config_path(self, config_path: str) -> Optional[Path]:
        """Resolve the configuration path to a concrete XML file."""

        path = Path(config_path).expanduser()
        if path.is_dir():
            xml_files = self.list_files_in_config_folder(str(path))
            if len(xml_files) == 1:
                return xml_files[0]
            self.logger.warning("Found %d XML files in %s", len(xml_files), path)
            return None

        if path.is_file() and path.suffix.lower() == ".xml":
            return path

        self.logger.warning("CIP configuration path is invalid: %s", path)
        return None

    def load_configuration(self, config_path: str) -> CIPConfigResult:
        """Load and validate the CIP configuration located at *config_path*."""

        resolved_path = self.resolve_cip_config_path(config_path)
        if not resolved_path:
            self.overall_cip_valid = False
            return CIPConfigResult(resolved_path=None, success=False)

        self.cip_xml_path = resolved_path
        self.cip_config_selected = resolved_path.name
        tests: List[Tuple[str, str]] = []

        test_success = self.check_cip_config()
        tests.append(("CIP XML Validity", "OK" if test_success else "FAILED"))

        success = all(status == "OK" for _, status in tests)
        self.cip_test_flag = success
        return CIPConfigResult(resolved_path=resolved_path, tests=tests, success=success)

    def check_cip_config(self) -> bool:
        """Validate the currently selected configuration file."""

        self.logger.info("Validating CIP configuration")

        xml_filepath = self.cip_xml_path
        if not xml_filepath:
            self.logger.error("No CIP configuration file has been provided")
            self.overall_cip_valid = False
            return False

        results: List[Tuple[str, str]] = []

        xml_path = Path(xml_filepath)
        config_folder = xml_path.parent
        if not config_folder.exists() or not config_folder.is_dir():
            self.logger.error("Config folder is invalid: %s", config_folder)
            self.overall_cip_valid = False
            return False

        xml_files = [file for file in config_folder.iterdir() if file.suffix.lower() == ".xml"]
        if not xml_files:
            results.append(("Detect XML in Config Folder", "FAILED"))
            self.logger.error("No XML files found in config folder: %s", config_folder)
            self.overall_cip_valid = False
            return False

        results.append(("Detect XML in Config Folder", "OK"))

        file_exists_status = "OK" if xml_path.exists() else "FAILED"
        results.append(("CIP Conf File Exists", file_exists_status))

        is_xml_status = "OK" if xml_path.suffix.lower() == ".xml" else "FAILED"
        results.append(("File is XML", is_xml_status))

        xml_parse_status = "SKIPPED"
        root: Optional[ET.Element] = None
        if file_exists_status == "OK" and is_xml_status == "OK":
            try:
                tree = ET.parse(xml_filepath)
                root = tree.getroot()
                self.root = root
                xml_parse_status = "OK"
            except ET.ParseError as exc:
                xml_parse_status = f"FAILED: {exc}"
                self.logger.exception("Failed to parse CIP XML")
        results.append(("Parse XML", xml_parse_status))

        if xml_parse_status == "OK" and root is not None:
            ot_eo_status = "OK" if self.check_ot_eo(root) else "FAILED"
            results.append(("One Assembly with Subtype 'OT_EO'", ot_eo_status))

            to_status = "OK" if self.check_to(root) else "FAILED"
            results.append(("One Assembly with Subtype 'TO'", to_status))

        overall_status = all(status == "OK" for _, status in results if status not in {"SKIPPED"})
        results.append(("Overall Status", "OK" if overall_status else "FAILED"))
        self.overall_cip_valid = overall_status

        # Store for later introspection from CLI
        self._latest_results = results  # type: ignore[attr-defined]
        return overall_status

    def latest_results(self) -> Sequence[Tuple[str, str]]:
        """Return the results from the latest configuration validation."""

        return getattr(self, "_latest_results", [])

    def check_ot_eo(self, root: ET.Element) -> bool:
        assemblies = root.findall("./assembly")
        ot_eo_assemblies = [
            assembly
            for assembly in assemblies
            if assembly.get("subtype") == "OT_EO" and len(assembly.findall("*")) >= 1
        ]
        try:
            self.ot_eo_assemblies = ot_eo_assemblies[0]
            layout = self.create_packet_class(ot_eo_assemblies[0])
            if layout is None:
                raise ValueError("Unable to build OT packet layout")
            packet = self._register_packet_layout(layout)
            self.logger.debug(
                "OT assembly size expected=%s formed=%s",
                layout.assembly_size // 8,
                len(packet),
            )
        except Exception:  # pragma: no cover - defensive
            self.logger.exception("OT Packet Initialization Failure")
        return len(ot_eo_assemblies) == 1

    def check_to(self, root: ET.Element) -> bool:
        assemblies = root.findall("./assembly")
        to_assemblies = [
            assembly
            for assembly in assemblies
            if assembly.get("subtype") == "TO" and len(assembly.findall("*")) >= 1
        ]
        try:
            self.to_assemblies = to_assemblies[0]
            layout = self.create_packet_class(to_assemblies[0])
            if layout is None:
                raise ValueError("Unable to build TO packet layout")
            packet = self._register_packet_layout(layout)
            self.logger.debug(
                "TO assembly size expected=%s formed=%s",
                layout.assembly_size // 8,
                len(packet),
            )
        except Exception:  # pragma: no cover - defensive
            self.logger.exception("TO Packet Initialization Failure")
        return len(to_assemblies) == 1

    # Packet construction helpers -------------------------------------------------
    def create_packet_dict(self, fields_dict: List[dict], assembly_size: int):
        max_packet_size_bits = assembly_size
        self.logger.info("Create_Packet_Dictionary()")
        signals = {}

        cip_data_type_size = {
            "usint": 1,
            "uint": 2,
            "udint": 4,
            "real": 4,
            "string": 1,
            "sint": 1,
            "int": 2,
            "dint": 4,
            "lreal": 8,
            "lint": 8,
        }

        fields_dict.sort(key=lambda item: item["offset"])
        self.logger.info("create_packet_dict: Sorted Fields")

        sorted_dict = {}
        for item in fields_dict:
            sorted_dict[item["id"]] = {
                "offset": item["offset"],
                "type": item["type"],
                "length": item["length"],
            }

        for field_id, field_info in sorted_dict.items():
            offset = field_info["offset"]
            field_type = field_info["type"]
            byte_index = offset // 8
            signals.setdefault(byte_index, [])
            if field_type == "bool":
                signals[byte_index].append(
                    {
                        "id": field_id,
                        "offset": offset,
                        "type": "bool",
                        "length": 1,
                    }
                )

        len_counter = 0
        temp_pad_index = 0
        temp_pad_len = 0
        for byte_index in range(max_packet_size_bits // 8):
            if len_counter != 0:
                len_counter -= 1
                continue

            pack = signals.get(byte_index, [])
            if not pack:
                signals[byte_index] = []
                field_data = None
                for field_id, field_info in sorted_dict.items():
                    if field_info["offset"] == byte_index * 8 and field_info["type"] != "bool":
                        field_data = (
                            field_id,
                            field_info["type"],
                            field_info["length"],
                        )
                        break

                if field_data:
                    if temp_pad_len > 0:
                        signals[temp_pad_index].append(
                            {
                                "id": f"spare_byte_{temp_pad_index}",
                                "offset": temp_pad_index * 8,
                                "type": "string",
                                "length": temp_pad_len,
                            }
                        )
                        temp_pad_len = 0
                        temp_pad_index = 0

                    field_name, field_type, field_length = field_data
                    signals[byte_index].append(
                        {
                            "id": field_name,
                            "offset": byte_index * 8,
                            "type": field_type,
                            "length": field_length,
                        }
                    )
                    len_counter_field_size = cip_data_type_size.get(field_type, 1)
                    len_counter = field_length * len_counter_field_size - 1
                else:
                    len_counter = 0
                    if temp_pad_len == 0:
                        temp_pad_index = byte_index
                    temp_pad_len += 1
            else:
                if temp_pad_len > 0:
                    signals[temp_pad_index].append(
                        {
                            "id": f"spare_byte_{temp_pad_index}",
                            "offset": temp_pad_index * 8,
                            "type": "string",
                            "length": temp_pad_len,
                        }
                    )
                    temp_pad_len = 0
                    temp_pad_index = 0

                occupied_offsets = {signal["offset"] % 8 for signal in pack}
                for bit_index in range(8):
                    if bit_index not in occupied_offsets:
                        bit_offset = byte_index * 8 + bit_index
                        signals[byte_index].append(
                            {
                                "id": f"spare_bit_{byte_index}_{bit_index}",
                                "offset": bit_offset,
                                "type": "bool",
                                "length": 1,
                            }
                        )
                signals[byte_index].sort(key=lambda x: x["offset"])

        if temp_pad_len > 0:
            signals[temp_pad_index].append(
                {
                    "id": f"spare_byte_{temp_pad_index}",
                    "offset": temp_pad_index * 8,
                    "type": "string",
                    "length": temp_pad_len,
                }
            )

        return signals

    def sorted_fields(self, packet):
        self.logger.info("sorted_fields()")
        fields = []
        for _, signals in packet.items():
            for signal in signals:
                fields.append(
                    {
                        "id": signal["id"],
                        "offset": signal["offset"],
                        "type": signal["type"],
                        "length": signal["length"],
                    }
                )

        fields = sorted(fields, key=lambda x: x["offset"])
        return fields

    def create_packet_class(self, assembly_element):
        self.logger.info("create_packet_class()")
        subtype = assembly_element.attrib["subtype"]
        assembly_size = int(assembly_element.attrib["size"])
        if subtype not in ["OT_EO", "TO"]:
            return None

        class_name = assembly_element.attrib["id"]
        fields_dict = []

        for field in assembly_element.findall(".//"):
            field_len = int(field.attrib.get("length", 1))
            fields_dict.append(
                {
                    "id": field.attrib["id"],
                    "offset": int(field.attrib["offset"]),
                    "type": field.tag,
                    "length": field_len,
                }
            )

        byte_packet_field = self.create_packet_dict(fields_dict, assembly_size)
        sorted_field = self.sorted_fields(byte_packet_field)
        field_desc = []

        for field in sorted_field:
            field_id = field["id"]
            field_type = field["type"]
            field_length = field["length"]

            if field_type == "usint":
                field_desc.append(scapy_all.ByteField(field_id, 0))
            elif field_type == "bool":
                field_desc.append(scapy_all.BitField(field_id, 0, 1))
            elif field_type == "real":
                field_desc.append(scapy_all.IEEEFloatField(field_id, 0))
            elif field_type == "string":
                field_desc.append(scapy_all.StrFixedLenField(field_id, b"", int(field_length)))
            elif field_type == "udint":
                field_desc.append(scapy_all.LEIntField(field_id, 0))
            elif field_type == "uint":
                field_desc.append(scapy_all.ShortField(field_id, 0))
            elif field_type == "sint":
                field_desc.append(scapy_all.SignedByteField(field_id, 0))

        dynamic_packet_class = type(class_name, (scapy_all.Packet,), {"name": class_name, "fields_desc": field_desc})
        return PacketLayout(
            name=class_name,
            subtype=subtype,
            assembly_size=assembly_size,
            packet_class=dynamic_packet_class,
            byte_map=byte_packet_field,
            fields=sorted_field,
        )

    # Shared packet helpers -------------------------------------------------------
    def _register_packet_layout(self, layout: PacketLayout) -> scapy_all.Packet:
        """Store *layout* and return the instantiated packet."""

        self._packet_layouts[layout.subtype] = layout
        packet = layout.packet_class()
        self._packet_instances[layout.subtype] = packet

        if layout.subtype == "OT_EO":
            self.OT_packet_class = layout.packet_class
            self.OT_packet = packet
        elif layout.subtype == "TO":
            self.TO_packet_class = layout.packet_class
            self.TO_packet = packet

        return packet

    def get_packet_layout(self, subtype: str) -> Optional[PacketLayout]:
        """Return the stored :class:`PacketLayout` for *subtype*."""

        return self._packet_layouts.get(subtype)

    def get_packet_layouts(self) -> Sequence[PacketLayout]:
        """Return all known packet layouts."""

        return tuple(self._packet_layouts.values())

    def get_packet_class(self, subtype: str):
        """Return the dynamically generated packet class for *subtype*."""

        layout = self.get_packet_layout(subtype)
        return layout.packet_class if layout else None

    def get_packet_instance(self, subtype: str):
        """Return the instantiated packet for *subtype* (if available)."""

        return self._packet_instances.get(subtype)

    def set_packet_instance(self, subtype: str, packet: scapy_all.Packet) -> None:
        """Store *packet* for *subtype* and keep legacy attributes in sync."""

        self._packet_instances[subtype] = packet
        if subtype == "OT_EO":
            self.OT_packet = packet
        elif subtype == "TO":
            self.TO_packet = packet

    def get_field_metadata(self, subtype: str) -> Sequence[dict]:
        """Return field metadata for the packet matching *subtype*."""

        layout = self.get_packet_layout(subtype)
        if not layout:
            return []
        return [field.copy() for field in layout.fields]


__all__ = ["CIPConfigService", "CIPConfigResult", "PacketLayout"]
