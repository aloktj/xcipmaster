import time

import pytest
from tests._stubs import install_common_stubs

install_common_stubs()
from scapy import all as scapy_all

from xcipmaster.fields import (
    FieldFormatter,
    FieldFormattingError,
    FieldMutator,
    FieldMutationError,
    WaveformError,
    WaveformManager,
)


class ExamplePacket(scapy_all.Packet):
    name = "Example"
    fields_desc = [
        scapy_all.IEEEFloatField("float_field", 0.0),
        scapy_all.BitField("bit_field", 0, 1),
        scapy_all.ByteField("byte_field", 0),
        scapy_all.ShortField("short_field", 0),
        scapy_all.StrFixedLenField("text_field", b"", length=4),
    ]


for _field in ExamplePacket.fields_desc:
    setattr(ExamplePacket, _field.name, _field)

def test_field_mutator_sets_and_clears_values():
    packet = ExamplePacket()
    mutator = FieldMutator()
    formatter = FieldFormatter()

    mutator.set_value(packet, "float_field", "1.5")
    assert pytest.approx(formatter.format_value(packet, "float_field"), rel=1e-6) == 1.5

    mutator.set_value(packet, "byte_field", "0x0f")
    assert getattr(packet, "byte_field") == 0x0F

    mutator.set_value(packet, "bit_field", "1")
    mutator.clear_value(packet, "bit_field")
    assert formatter.format_value(packet, "bit_field") == 0

    mutator.set_value(packet, "text_field", "abc")
    assert formatter.format_value(packet, "text_field") == b"abc"


def test_field_mutator_rejects_invalid_values():
    packet = ExamplePacket()
    mutator = FieldMutator()

    with pytest.raises(FieldMutationError):
        mutator.set_value(packet, "byte_field", "invalid")

    with pytest.raises(FieldMutationError):
        mutator.set_value(packet, "text_field", "toolong")


def test_field_formatter_errors_for_unknown_field():
    packet = ExamplePacket()
    formatter = FieldFormatter()

    with pytest.raises(FieldFormattingError):
        formatter.format_value(packet, "missing")


class RecordingMutator(FieldMutator):
    def __init__(self):
        super().__init__()
        self.calls = []

    def set_value(self, packet, field_name, raw_value):  # type: ignore[override]
        self.calls.append((field_name, raw_value))
        return super().set_value(packet, field_name, raw_value)


class FastClock:
    def __init__(self):
        self.current = time.time()

    def time(self):
        return self.current

    def sleep(self, duration):
        self.current += duration


def test_waveform_manager_generates_values():
    packet = ExamplePacket()
    mutator = RecordingMutator()
    clock = FastClock()
    manager = WaveformManager(lambda: packet, mutator, sample_interval=0.001, time_module=clock)

    manager.start_wave("float_field", 2.0, 0.0, 100)
    time.sleep(0.01)
    manager.stop_wave("float_field")

    assert mutator.calls, "Waveform manager should invoke the mutator"


def test_waveform_manager_validates_fields():
    packet = ExamplePacket()
    mutator = FieldMutator()
    manager = WaveformManager(lambda: packet, mutator)

    with pytest.raises(WaveformError):
        manager.start_wave("byte_field", 1, 0, 100)


def test_waveform_manager_stop_all_returns_fields():
    packet = ExamplePacket()
    mutator = FieldMutator()
    manager = WaveformManager(lambda: packet, mutator)

    manager.start_wave("float_field", 1, 0, 100)
    time.sleep(0.01)
    stopped = manager.stop_all()

    assert tuple(stopped)  # should contain at least the floating field name
