# xcipmaster

XCIP Master is a command-line utility for validating Common Industrial Protocol
(CIP) configurations, exercising mock network traffic, and driving waveform
generators for device testing.

## Installation

The project is distributed as a standard Python package targeting Python 3.10+
and the latest Scapy releases. To install it into the current environment::

    python -m pip install .

An editable install for development can be created with::

    python -m pip install -e .[packaging]

The optional ``packaging`` extra pulls in PyInstaller so that self-contained
executables can be generated for specific platforms.

## Usage

Once installed, the ``xcipmaster`` command becomes available. Run ``--help`` to
discover the interactive shell and subcommands::

    xcipmaster --help

The tool ships with a bundled demonstration configuration located at
``xcipmaster/conf/cip_xml_config.xml``. When invoked without a ``--config``
argument the CLI automatically loads this configuration. Supply a directory or
file path to validate custom CIP XML manifests.

## Testing helpers

Unit tests can instantiate the command controller directly with stubbed
dependencies. The :class:`CLI` constructor accepts optional services and a
``test_mode`` flag that skips the interactive banner, progress bar, and startup
prompts. For example::

    fake_cli = CLI(
        config_service=FakeConfigService(),
        network_service=FakeNetworkService(),
        comm_manager=FakeCommManager(),
        test_mode=True,
    )

The object can then be passed to Click's ``CliRunner`` via ``obj=fake_cli`` to
exercise commands without touching the real filesystem or network.
