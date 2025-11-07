"""User-interface helpers for the CIP CLI."""

import sys
import time
from typing import Generator

import click
import pyfiglet
from termcolor import colored
from tabulate import tabulate


class UIUtilities:
    """Mixin providing banner and progress utilities for the CLI."""

    def spinning_cursor(self) -> Generator[str, None, None]:
        while True:
            for cursor in "|/-\\":
                yield cursor

    def loading_message(self, message: str, duration: float) -> None:
        spinner = self.spinning_cursor()
        sys.stdout.write(message)
        sys.stdout.flush()
        start_time = time.time()
        while time.time() - start_time < duration:
            sys.stdout.write(next(spinner))
            sys.stdout.flush()
            time.sleep(0.1)
            sys.stdout.write("\b")
        sys.stdout.write("\r")  # Move cursor to the beginning of the line
        sys.stdout.write(" " * len(message))  # Clear the loading message
        sys.stdout.write("\r")  # Move cursor to the beginning of the line
        sys.stdout.flush()

    def progress_bar(self, message: str, duration: float) -> None:
        click.echo("\n")
        total_ticks = 75  # Number of ticks in the progress bar
        start_time = time.time()
        while time.time() - start_time < duration:
            elapsed_time = time.time() - start_time
            progress = min(int((elapsed_time / duration) * total_ticks), total_ticks)
            remaining = total_ticks - progress
            bar = "[" + "=" * progress + " " * remaining + "]"
            sys.stdout.write("\r")
            sys.stdout.write(f"{message} {bar} {elapsed_time:.1f}s/{duration:.1f}s")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\n")
        click.echo("\n")

    def display_banner(self) -> None:
        table_width = 75

        click.echo("\n\n")
        banner_text = pyfiglet.figlet_format(
            "\t\t\t\t\t CIP Tool \t\t\t\t\t", font="slant"
        )
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
