"""Entry point for the xcipmaster CLI."""

from xcipmaster.cli.commands import cli

__all__ = ["cli"]

if __name__ == "__main__":
    cli()
