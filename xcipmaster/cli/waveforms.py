"""Waveform helpers for the CIP CLI."""

import math
import struct
import threading
import time
from typing import Dict

import click
from scapy import all as scapy_all


class WaveformUtilities:
    """Mixin providing waveform generation helpers."""

    stop_events: Dict[str, threading.Event]

    def __init__(self, *args, **kwargs):  # type: ignore[override]
        super().__init__(*args, **kwargs)  # type: ignore[misc]
        if not hasattr(self, "stop_events"):
            self.stop_events = {}

    def _float_to_big_endian_float(self, value):
        byte_array = struct.pack("f", float(value))
        reversed_byte_array = byte_array[::-1]
        return struct.unpack("f", reversed_byte_array)[0]

    def wave_field(self, field_name, max_value, min_value, period_ms):
        self.logger.info("Executing wave_field function")
        self.stop_wave(field_name)
        field = getattr(self.ot_packet.__class__, field_name)
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
                    wave_value = (
                        amplitude * math.sin(2 * math.pi * elapsed_time / period_ms)
                        + offset
                    )

                    bE_field_value = self._float_to_big_endian_float(wave_value)
                    with self.lock:
                        setattr(self.ot_packet, field_name, bE_field_value)

                    time.sleep(0.01)  # Adjust sleep time as needed

            self.stop_events[field_name] = threading.Event()
            wave_thread_instance = threading.Thread(target=wave_thread)
            wave_thread_instance.start()
            print(
                f"Waving {field_name} from {min_value} to {max_value} every {period_ms} milliseconds."
            )
        else:
            print(f"Field {field_name} is not of type IEEEFloatField and cannot be waved.")

    def tria_field(self, field_name, max_value, min_value, period_ms):
        self.logger.info("Executing tria_field function")
        self.stop_wave(field_name)
        field = getattr(self.ot_packet.__class__, field_name)
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
                    wave_value = (
                        amplitude * (2 * abs(phase - math.floor(phase + 0.5)) - 1)
                    ) + offset
                    bE_field_value = self._float_to_big_endian_float(wave_value)
                    with self.lock:
                        setattr(self.ot_packet, field_name, bE_field_value)
                    time.sleep(0.01)  # Adjust sleep time as needed

            self.stop_events[field_name] = threading.Event()
            wave_thread_instance = threading.Thread(target=tria_wave_thread)
            wave_thread_instance.start()
            print(
                f"Generating triangular wave for {field_name} every {period_ms} milliseconds."
            )
        else:
            print(f"Field {field_name} is not of type IEEEFloatField and cannot be waved.")

    def box_field(self, field_name, max_value, min_value, period_ms, duty_cycle):
        self.logger.info("Executing box_field function")
        self.stop_wave(field_name)
        field = getattr(self.ot_packet.__class__, field_name)
        if isinstance(field, scapy_all.IEEEFloatField):
            max_value = float(max_value)
            min_value = float(min_value)
            period_ms = float(period_ms) / 1000  # Convert milliseconds to seconds
            duty_cycle = float(duty_cycle)

            def box_wave_thread():
                self.logger.info("Executing box_wave_thread function")
                start_time = time.time()
                while not self.stop_events[field_name].is_set():
                    current_time = time.time()
                    elapsed_time = current_time - start_time
                    duty_period = period_ms * duty_cycle
                    wave_value = (
                        max_value if (elapsed_time % period_ms) < duty_period else min_value
                    )
                    bE_field_value = self._float_to_big_endian_float(wave_value)
                    with self.lock:
                        setattr(self.ot_packet, field_name, bE_field_value)
                    time.sleep(0.01)  # Adjust sleep time as needed

            self.stop_events[field_name] = threading.Event()
            wave_thread_instance = threading.Thread(target=box_wave_thread)
            wave_thread_instance.start()
            print(
                f"Generating square wave for {field_name} with duty cycle {duty_cycle} every {period_ms} milliseconds."
            )
        else:
            print(f"Field {field_name} is not of type IEEEFloatField and cannot be waved.")

    def stop_all_thread(self):
        self.logger.info(
            f"{self.stop_all_thread.__name__}: Stopping all wave threads for domain"
        )
        for field_name in self.stop_events:
            self.stop_events[field_name].set()
            click.echo(
                f"{self.stop_all_thread.__name__}: Waving for '{field_name}' has been stopped"
            )
        self.logger.info(
            f"{self.stop_all_thread.__name__}: All wave threads have been successfully stopped"
        )

    def stop_wave(self, field_name):
        self.logger.info("Executing stop_wave function")
        if field_name in self.stop_events and not self.stop_events[field_name].is_set():
            self.stop_events[field_name].set()
            click.echo(f"\nWaving for '{field_name}' has been stopped.\n")
