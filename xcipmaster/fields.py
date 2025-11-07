"""Field and waveform helper utilities for the CIP CLI."""

from __future__ import annotations

import math
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

from scapy import all as scapy_all


class FieldMutationError(ValueError):
    """Raised when a field cannot be mutated."""


class FieldFormattingError(ValueError):
    """Raised when a field cannot be formatted for display."""


class WaveformError(RuntimeError):
    """Raised when waveform generation cannot be performed."""


FieldSetter = Callable[[Any, str, Any], Any]
FieldClearer = Callable[[Any, str], Any]
FieldFormatterCallable = Callable[[Any, str], Any]


@dataclass(frozen=True)
class FieldStrategy:
    """Container describing how to mutate and format a Scapy field."""

    setter: Optional[FieldSetter] = None
    clearer: Optional[FieldClearer] = None
    formatter: Optional[FieldFormatterCallable] = None


def _reverse_bytes(value: int, length: int) -> int:
    raw = int(value)
    byte_array = raw.to_bytes(length, byteorder="big", signed=False)
    return int.from_bytes(byte_array[::-1], byteorder="big", signed=False)


def _float_to_big_endian(value: float) -> float:
    byte_array = struct.pack("f", float(value))
    reversed_byte_array = byte_array[::-1]
    return struct.unpack("f", reversed_byte_array)[0]


def _parse_int(value: Any) -> int:
    if isinstance(value, (int, float)):
        return int(value)

    if not isinstance(value, str):
        raise FieldMutationError("Value must be numeric or a hexadecimal string.")

    stripped = value.strip().lower()
    if stripped.startswith("0x"):
        try:
            return int(stripped, 16)
        except ValueError as exc:  # pragma: no cover - defensive guard
            raise FieldMutationError("Invalid hexadecimal value.") from exc
    try:
        return int(stripped, 10)
    except ValueError as exc:  # pragma: no cover - defensive guard
        raise FieldMutationError("Value must be numeric or a hexadecimal string.") from exc


def _ensure_range(value: int, minimum: int, maximum: int, *, field_name: str) -> int:
    if not minimum <= value <= maximum:
        raise FieldMutationError(
            f"Field {field_name} expects an integer value between {minimum} and {maximum}."
        )
    return value


def _string_to_bytes(packet: Any, field_name: str, raw_value: Any) -> bytes:
    field = getattr(packet.__class__, field_name)
    if isinstance(raw_value, bytes):
        field_bytes = raw_value
    elif isinstance(raw_value, str):
        field_bytes = raw_value.encode()
    else:
        raise FieldMutationError(
            f"Field {field_name} expects a string or bytes value."
        )

    max_length = field.length_from(packet)
    if len(field_bytes) > max_length:
        raise FieldMutationError(
            f"Field {field_name} expects a string of length up to {max_length}."
        )
    return field_bytes


def _format_numeric(packet: Any, field_name: str, *, length: int) -> int:
    field_value = getattr(packet, field_name)
    return _reverse_bytes(int(field_value), length)


def _format_float(packet: Any, field_name: str) -> float:
    field_value = getattr(packet, field_name)
    return _float_to_big_endian(float(field_value))


def _format_string(packet: Any, field_name: str) -> Any:
    return getattr(packet, field_name)


def _set_float(packet: Any, field_name: str, raw_value: Any) -> float:
    try:
        numeric_value = float(raw_value)
    except (TypeError, ValueError) as exc:
        raise FieldMutationError(f"Field {field_name} expects a float value.") from exc

    be_value = _float_to_big_endian(numeric_value)
    setattr(packet, field_name, be_value)
    return numeric_value


def _clear_float(packet: Any, field_name: str) -> float:
    setattr(packet, field_name, 0.0)
    return 0.0


def _set_bit(packet: Any, field_name: str, raw_value: Any) -> int:
    if raw_value in {0, 1}:
        int_value = int(raw_value)
    elif isinstance(raw_value, str) and raw_value in {"0", "1"}:
        int_value = int(raw_value)
    else:
        raise FieldMutationError(
            f"Field {field_name} expects a value of either '0' or '1'."
        )
    setattr(packet, field_name, int_value)
    return int_value


def _clear_int(packet: Any, field_name: str) -> int:
    setattr(packet, field_name, 0)
    return 0


def _set_byte(packet: Any, field_name: str, raw_value: Any) -> int:
    value = _parse_int(raw_value)
    int_value = _ensure_range(value, 0, 0xFF, field_name=field_name)
    setattr(packet, field_name, int_value)
    return int_value


def _set_short(packet: Any, field_name: str, raw_value: Any) -> int:
    value = _parse_int(raw_value)
    int_value = _ensure_range(value, 0, 0xFFFF, field_name=field_name)
    converted = _reverse_bytes(int_value, 2)
    setattr(packet, field_name, converted)
    return int_value


def _set_le_short(packet: Any, field_name: str, raw_value: Any) -> Any:
    value = _parse_int(raw_value)
    int_value = _ensure_range(value, 0, 0xFFFF, field_name=field_name)
    field = getattr(packet.__class__, field_name)
    if isinstance(raw_value, str) and raw_value.strip().lower().startswith("0x"):
        stored_value = int_value.to_bytes(2, byteorder="big", signed=False)
    else:
        stored_value = int_value
    setattr(packet, field_name, stored_value)
    return int_value


def _set_double(packet: Any, field_name: str, raw_value: Any) -> float:
    value = _parse_int(raw_value)
    if not 0 <= value <= (2**64 - 1):
        raise FieldMutationError("Value out of range for IEEEDoubleField")
    setattr(packet, field_name, float(value))
    return float(value)


def _clear_string(packet: Any, field_name: str) -> bytes:
    setattr(packet, field_name, b"")
    return b""


def _set_fixed_string(packet: Any, field_name: str, raw_value: Any) -> bytes:
    field_bytes = _string_to_bytes(packet, field_name, raw_value)
    setattr(packet, field_name, field_bytes)
    return field_bytes


DEFAULT_FIELD_STRATEGIES: Dict[type, FieldStrategy] = {
    scapy_all.IEEEFloatField: FieldStrategy(
        setter=_set_float,
        clearer=_clear_float,
        formatter=_format_float,
    ),
    scapy_all.BitField: FieldStrategy(
        setter=_set_bit,
        clearer=_clear_int,
        formatter=lambda packet, name: _format_numeric(packet, name, length=1),
    ),
    scapy_all.ByteField: FieldStrategy(
        setter=_set_byte,
        clearer=_clear_int,
        formatter=lambda packet, name: _format_numeric(packet, name, length=1),
    ),
    scapy_all.ShortField: FieldStrategy(
        setter=_set_short,
        clearer=_clear_int,
        formatter=lambda packet, name: _format_numeric(packet, name, length=2),
    ),
    scapy_all.LEShortField: FieldStrategy(
        setter=_set_le_short,
        clearer=_clear_int,
        formatter=lambda packet, name: _format_numeric(packet, name, length=2),
    ),
    scapy_all.IntField: FieldStrategy(
        clearer=_clear_int,
        formatter=lambda packet, name: _format_numeric(packet, name, length=4),
    ),
    scapy_all.LongField: FieldStrategy(
        clearer=_clear_int,
        formatter=lambda packet, name: _format_numeric(packet, name, length=8),
    ),
    scapy_all.StrField: FieldStrategy(formatter=_format_string),
    scapy_all.StrFixedLenField: FieldStrategy(
        setter=_set_fixed_string,
        clearer=_clear_string,
        formatter=_format_string,
    ),
    scapy_all.IEEEDoubleField: FieldStrategy(
        setter=_set_double,
        clearer=_clear_float,
        formatter=_format_float,
    ),
}


class FieldMutator:
    """Provide high-level helpers for mutating packet fields."""

    def __init__(self, strategies: Optional[Dict[type, FieldStrategy]] = None):
        self._strategies = strategies or DEFAULT_FIELD_STRATEGIES

    def set_value(self, packet: Any, field_name: str, raw_value: Any) -> Any:
        field, strategy = self._resolve_strategy(packet, field_name, require_setter=True)
        assert strategy.setter is not None  # for mypy/static analyzers
        return strategy.setter(packet, field_name, raw_value)

    def clear_value(self, packet: Any, field_name: str) -> Any:
        field, strategy = self._resolve_strategy(packet, field_name, require_clearer=True)
        if strategy.clearer is None:
            raise FieldMutationError(
                f"Cannot clear field {field_name}: unsupported field type."
            )
        return strategy.clearer(packet, field_name)

    def _resolve_strategy(
        self,
        packet: Any,
        field_name: str,
        *,
        require_setter: bool = False,
        require_clearer: bool = False,
    ) -> Tuple[Any, FieldStrategy]:
        field = getattr(packet.__class__, field_name, None)
        if field is None:
            raise FieldMutationError(f"Field {field_name} not found.")

        strategy = self._lookup_strategy(field)
        if strategy is None:
            raise FieldMutationError(
                f"Field {field_name} is not supported for this operation."
            )

        if require_setter and strategy.setter is None:
            raise FieldMutationError(
                f"Field {field_name} is not supported for this operation."
            )
        if require_clearer and strategy.clearer is None:
            raise FieldMutationError(
                f"Cannot clear field {field_name}: unsupported field type."
            )
        return field, strategy

    def _lookup_strategy(self, field: Any) -> Optional[FieldStrategy]:
        for field_type, strategy in self._strategies.items():
            if isinstance(field, field_type):
                return strategy
        return None


class FieldFormatter:
    """Format packet fields for display to the user."""

    def __init__(self, strategies: Optional[Dict[type, FieldStrategy]] = None):
        self._strategies = strategies or DEFAULT_FIELD_STRATEGIES

    def format_value(self, packet: Any, field_name: str) -> Any:
        field = getattr(packet.__class__, field_name, None)
        if field is None:
            raise FieldFormattingError(f"Field {field_name} not found.")

        strategy = self._lookup_strategy(field)
        if strategy is None or strategy.formatter is None:
            raise FieldFormattingError(
                f"Field {field_name} cannot be formatted for display."
            )
        return strategy.formatter(packet, field_name)

    def _lookup_strategy(self, field: Any) -> Optional[FieldStrategy]:
        for field_type, strategy in self._strategies.items():
            if isinstance(field, field_type):
                return strategy
        return None


class WaveformManager:
    """Manage waveform threads for mutating IEEE float fields."""

    def __init__(
        self,
        packet_supplier: Callable[[], Any],
        field_mutator: FieldMutator,
        *,
        lock: Optional[threading.Lock] = None,
        sample_interval: float = 0.01,
        time_module: Any = None,
    ) -> None:
        self._packet_supplier = packet_supplier
        self._field_mutator = field_mutator
        self._lock = lock or threading.Lock()
        self._sample_interval = sample_interval
        self._time = time_module if time_module is not None else time
        self._stop_events: Dict[str, threading.Event] = {}
        self._threads: Dict[str, threading.Thread] = {}

    def start_wave(
        self,
        field_name: str,
        max_value: Any,
        min_value: Any,
        period_ms: Any,
    ) -> None:
        max_float, min_float, period_s = self._normalize_wave_inputs(
            field_name, max_value, min_value, period_ms
        )
        amplitude = (max_float - min_float) / 2
        offset = (max_float + min_float) / 2

        def compute(elapsed: float, period: float) -> float:
            return amplitude * math.sin(2 * math.pi * elapsed / period) + offset

        self._launch_wave(field_name, period_s, compute)

    def start_triangle_wave(
        self,
        field_name: str,
        max_value: Any,
        min_value: Any,
        period_ms: Any,
    ) -> None:
        max_float, min_float, period_s = self._normalize_wave_inputs(
            field_name, max_value, min_value, period_ms
        )
        amplitude = (max_float - min_float) / 2
        offset = (max_float + min_float) / 2

        def compute(elapsed: float, period: float) -> float:
            phase = elapsed / period
            return amplitude * (2 * abs(phase - math.floor(phase + 0.5)) - 1) + offset

        self._launch_wave(field_name, period_s, compute)

    def start_square_wave(
        self,
        field_name: str,
        max_value: Any,
        min_value: Any,
        period_ms: Any,
        duty_cycle: Any,
    ) -> None:
        max_float, min_float, period_s = self._normalize_wave_inputs(
            field_name, max_value, min_value, period_ms
        )
        try:
            duty_float = float(duty_cycle)
        except (TypeError, ValueError) as exc:
            raise WaveformError("Duty cycle must be numeric.") from exc

        duty_float = max(0.0, min(1.0, duty_float))

        def compute(elapsed: float, period: float) -> float:
            duty_period = period * duty_float
            return max_float if (elapsed % period) < duty_period else min_float

        self._launch_wave(field_name, period_s, compute)

    def stop_wave(self, field_name: str) -> bool:
        event = self._stop_events.pop(field_name, None)
        thread = self._threads.pop(field_name, None)
        if event is None:
            return False
        event.set()
        if thread and thread.is_alive():  # pragma: no branch - best effort cleanup
            thread.join(timeout=0.5)
        return True

    def stop_all(self) -> Tuple[str, ...]:
        stopped: list[str] = []
        for name in list(self._stop_events.keys()):
            if self.stop_wave(name):
                stopped.append(name)
        return tuple(stopped)

    def _normalize_wave_inputs(
        self, field_name: str, max_value: Any, min_value: Any, period_ms: Any
    ) -> Tuple[float, float, float]:
        self._resolve_float_field(field_name)
        try:
            max_float = float(max_value)
            min_float = float(min_value)
            period_float = float(period_ms) / 1000.0
        except (TypeError, ValueError) as exc:
            raise WaveformError("Wave parameters must be numeric.") from exc

        if period_float <= 0:
            raise WaveformError("Period must be greater than zero.")
        return max_float, min_float, period_float

    def _resolve_float_field(self, field_name: str) -> Tuple[Any, Any]:
        packet = self._packet_supplier()
        if packet is None:
            raise WaveformError("Packet is not available for waveform generation.")
        field = getattr(packet.__class__, field_name, None)
        if field is None:
            raise WaveformError(f"Field {field_name} not found.")
        if not isinstance(field, scapy_all.IEEEFloatField):
            raise WaveformError(
                f"Field {field_name} is not of type IEEEFloatField and cannot be waved."
            )
        return packet, field

    def _launch_wave(
        self,
        field_name: str,
        period_s: float,
        compute_value: Callable[[float, float], float],
    ) -> None:
        self.stop_wave(field_name)

        event = threading.Event()
        self._stop_events[field_name] = event

        def runner() -> None:
            start_time = self._time.time()
            while not event.is_set():
                current_time = self._time.time()
                elapsed = current_time - start_time
                packet = self._packet_supplier()
                if packet is None:
                    event.set()
                    break
                value = compute_value(elapsed, period_s)
                with self._lock:
                    self._field_mutator.set_value(packet, field_name, value)
                self._time.sleep(self._sample_interval)

        thread = threading.Thread(target=runner, name=f"wave-{field_name}", daemon=True)
        self._threads[field_name] = thread
        thread.start()


__all__ = [
    "FieldFormatter",
    "FieldFormattingError",
    "FieldMutationError",
    "FieldMutator",
    "WaveformError",
    "WaveformManager",
]
