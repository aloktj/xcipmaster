"""Command definitions for the CIP CLI."""

from pathlib import Path
from typing import Callable

import cmd as cmd_module
import shlex
import time

import click

from .controller import CLI
from xcipmaster.paths import default_config_directory


ENABLE_NETWORK = True


def _initialize_controller(
    ctx: click.Context, factory: Callable[[], CLI] = CLI
) -> CLI:
    """Create and prepare the :class:`CLI` controller for interactive sessions.

    Tests can supply a custom ``factory`` (for example ``lambda: CLI(test_mode=True)``)
    to inject stub services and bypass the interactive startup behaviour.
    """

    controller = factory()

    if not controller.test_mode and not ctx.resilient_parsing:
        controller.display_banner()
        controller.progress_bar("Initializing", 1)

        invoked_command = ctx.invoked_subcommand
        has_subcommand = bool(invoked_command or ctx.args)

        if not has_subcommand and controller.cip_test_flag:
            if not click.confirm("Do you want to continue?", default=True):
                click.echo("Exiting...")
                ctx.exit()

        if not has_subcommand:
            if not controller.ensure_configuration(controller.default_config_path):
                raise click.ClickException("CIP configuration failed during initialization.")

            if ENABLE_NETWORK:
                target_ip = click.prompt(
                    "Target IP address",
                    default=controller.target_ip,
                    show_default=True,
                )
                multicast_ip = click.prompt(
                    "Multicast group address",
                    default=controller.multicast_ip,
                    show_default=True,
                )

                if not controller.ensure_network_configuration(
                    target_ip, multicast_ip, force=True
                ):
                    raise click.ClickException(
                        "Network configuration failed during initialization."
                    )

    return controller


pass_controller = click.make_pass_decorator(CLI)


class CIPShell(cmd_module.Cmd):
    prompt = "cip> "
    intro = "Type 'help' to list commands. Type 'exit' or 'quit' to leave."

    def __init__(self, ctx: click.Context):
        super().__init__()
        self.ctx = ctx

    def do_exit(self, arg):  # pragma: no cover - interactive helper
        """Exit the interactive shell."""
        return True

    do_quit = do_exit  # pragma: no cover

    def do_help(self, arg):  # pragma: no cover - interactive helper
        args = shlex.split(arg)
        if not args:
            self.ctx.invoke(help_command)
            return

        command = self.ctx.command.get_command(self.ctx, args[0])
        if command is None:
            click.echo(f"Unknown command: {args[0]}")
            return

        with command.make_context(command.name, args[1:], parent=self.ctx) as cmd_ctx:
            click.echo(command.get_help(cmd_ctx))

    def default(self, line):  # pragma: no cover - interactive helper
        args = shlex.split(line)
        if not args:
            return

        command = self.ctx.command.get_command(self.ctx, args[0])
        if command is None:
            click.echo(f"Unknown command: {args[0]}")
            return

        try:
            with command.make_context(command.name, args[1:], parent=self.ctx) as cmd_ctx:
                command.invoke(cmd_ctx)
        except click.ClickException as exc:
            exc.show()
        except click.exceptions.Exit:
            pass


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """CIP Tool command-line interface."""
    if ctx.obj is None and not ctx.resilient_parsing:
        ctx.obj = _initialize_controller(ctx, CLI)

    if ctx.invoked_subcommand is None and not ctx.args and not ctx.resilient_parsing:
        ctx.invoke(cmd_shell)


@cli.command()
@pass_controller
def start(controller: CLI):
    """Validate configuration, test networking, and start communication."""

    if controller.enable_auto_reconnect:
        click.echo("Disabled auto-Connect using the CMD: <man> and try again !!!")
        return

    if not controller.ensure_configuration():
        raise click.ClickException("CIP configuration failed.")

    if ENABLE_NETWORK:
        current_ip = getattr(controller.network_service, "ip_address", None)
        current_multicast = getattr(
            controller.network_service, "user_multicast_address", None
        )

        if current_ip is None or current_multicast is None:
            if controller.test_mode:
                target_ip = controller.target_ip
                multicast_ip = controller.multicast_ip
            else:
                target_ip = click.prompt(
                    "Target IP address", default=controller.target_ip, show_default=True
                )
                multicast_ip = click.prompt(
                    "Multicast group address",
                    default=controller.multicast_ip,
                    show_default=True,
                )

            if not controller.ensure_network_configuration(
                target_ip, multicast_ip, force=True
            ):
                raise click.ClickException("Network configuration failed.")
        elif not controller.ensure_network_configuration():
            raise click.ClickException("Network configuration failed.")

    click.echo("Attempting to Start communication...")
    controller.comm_manager.start()

    try:
        while (
            controller.start_comm_thread_instance is not None
            and controller.start_comm_thread_instance.is_alive()
        ):
            controller.start_comm_thread_instance.join(timeout=0.5)
    except KeyboardInterrupt:
        click.echo("\nStopping communication...")
        controller.comm_manager.stop()


@cli.command()
@pass_controller
def stop(controller: CLI):
    """Stop communication."""
    if controller.enable_auto_reconnect:
        click.echo("Disabled auto-Connect using the CMD: <man> and try again !!!")
        return

    click.echo("Attempting to Stop communication...")
    controller.comm_manager.stop()


@cli.command()
@pass_controller
def auto(controller: CLI):
    """Enable auto-reconnect and start communication."""
    if controller.enable_auto_reconnect:
        click.echo("Already in auto-reconnect mode.")
        return

    if not controller.ensure_configuration():
        raise click.ClickException("CIP configuration failed.")

    if ENABLE_NETWORK and not controller.ensure_network_configuration():
        raise click.ClickException("Network configuration failed.")

    click.echo("Switching to Auto-Reconnect Mode!")
    controller.comm_manager.enable_auto()
    controller.comm_manager.start()

    try:
        while (
            controller.start_comm_thread_instance is not None
            and controller.start_comm_thread_instance.is_alive()
        ):
            controller.start_comm_thread_instance.join(timeout=0.5)
    except KeyboardInterrupt:
        click.echo("\nStopping communication...")
        controller.comm_manager.stop()


@cli.command()
@pass_controller
def man(controller: CLI):
    """Switch to manual communication mode."""
    if controller.enable_auto_reconnect:
        click.echo("Switching to Manual Connect Mode!")
        controller.comm_manager.disable_auto()
        time.sleep(2)
    else:
        click.echo("Already in manual mode")


@cli.command("set")
@click.argument("field_name")
@click.argument("value")
@pass_controller
def set_field_command(controller: CLI, field_name: str, value: str):
    """Set a field value."""
    if not controller.ensure_configuration():
        raise click.ClickException("CIP configuration failed.")
    controller.set_field(field_name, value)


@cli.command("clear")
@click.argument("field_name")
@pass_controller
def clear_field_command(controller: CLI, field_name: str):
    """Clear a field value."""
    if not controller.ensure_configuration():
        raise click.ClickException("CIP configuration failed.")
    controller.clear_field(field_name)


@cli.command("get")
@click.argument("field_name")
@pass_controller
def get_field_command(controller: CLI, field_name: str):
    """Get the current value of a field."""
    if not controller.ensure_configuration():
        raise click.ClickException("CIP configuration failed.")
    controller.get_field(field_name)


@cli.command("frame")
@pass_controller
def frame_command(controller: CLI):
    """Print the packet header and payload."""
    if not controller.ensure_configuration():
        raise click.ClickException("CIP configuration failed.")
    controller.print_frame()


@cli.command("fields")
@pass_controller
def fields_command(controller: CLI):
    """Display available fields."""
    if not controller.ensure_configuration():
        raise click.ClickException("CIP configuration failed.")
    controller.list_fields()


@cli.command("wave")
@click.argument("field_name")
@click.argument("max_value", type=float)
@click.argument("min_value", type=float)
@click.argument("period", type=int)
@pass_controller
def wave_command(controller: CLI, field_name: str, max_value: float, min_value: float, period: int):
    """Start a sine waveform for a field."""
    if not controller.ensure_configuration():
        raise click.ClickException("CIP configuration failed.")
    controller.wave_field(field_name, max_value, min_value, period)


@cli.command("tria")
@click.argument("field_name")
@click.argument("max_value", type=float)
@click.argument("min_value", type=float)
@click.argument("period", type=int)
@pass_controller
def tria_command(controller: CLI, field_name: str, max_value: float, min_value: float, period: int):
    """Start a triangular waveform for a field."""
    if not controller.ensure_configuration():
        raise click.ClickException("CIP configuration failed.")
    controller.tria_field(field_name, max_value, min_value, period)


@cli.command("box")
@click.argument("field_name")
@click.argument("max_value", type=float)
@click.argument("min_value", type=float)
@click.argument("period", type=int)
@click.argument("duty_cycle", type=float)
@pass_controller
def box_command(
    controller: CLI,
    field_name: str,
    max_value: float,
    min_value: float,
    period: int,
    duty_cycle: float,
):
    """Start a square waveform for a field."""
    if not controller.ensure_configuration():
        raise click.ClickException("CIP configuration failed.")
    controller.box_field(field_name, max_value, min_value, period, duty_cycle)


@cli.command("live")
@click.argument("refresh_rate", type=float)
@pass_controller
def live_command(controller: CLI, refresh_rate: float):
    """Display live field data."""
    if not controller.ensure_configuration():
        raise click.ClickException("CIP configuration failed.")
    controller.live_field_data(refresh_rate)


@cli.command("stop_wave")
@click.argument("field_name")
@pass_controller
def stop_wave_command(controller: CLI, field_name: str):
    """Stop waveform generation for a field."""
    if not controller.ensure_configuration():
        raise click.ClickException("CIP configuration failed.")
    controller.stop_wave(field_name)


@cli.command("cip-config")
@pass_controller
def cip_config_command(controller: CLI):
    """Run CIP configuration tests."""

    base_path = Path(controller.default_config_path or default_config_directory())
    config_dir = base_path if base_path.is_dir() else base_path.parent

    if not config_dir.exists():
        raise click.ClickException(
            f"Configuration directory not found: {config_dir}")

    xml_files = controller.list_files_in_config_folder(str(config_dir))
    if not xml_files:
        raise click.ClickException("No CIP configuration files found.")

    default_selection = None
    current_config = getattr(controller.config_service, "cip_xml_path", None)

    def _index_for(path_obj: Path):
        try:
            return xml_files.index(path_obj) + 1
        except ValueError:
            return None

    if current_config is not None:
        default_selection = _index_for(Path(current_config))
    if default_selection is None and controller.default_config_path:
        default_selection = _index_for(Path(controller.default_config_path))
    if default_selection is None:
        default_selection = 1

    selection = click.prompt(
        "Select configuration file",
        type=click.IntRange(1, len(xml_files)),
        default=default_selection,
        show_default=True,
    )

    selected_path = xml_files[selection - 1]

    if not controller.cip_config(str(selected_path), force=True):
        raise click.ClickException("CIP configuration failed.")


@cli.command("test-net")
@click.option(
    "--target-ip",
    default=None,
    help="Target device IP address. Defaults to the current setting.",
)
@click.option(
    "--multicast-ip",
    default=None,
    help="Multicast group IP address for network tests. Defaults to the current setting.",
)
@pass_controller
def test_net_command(controller: CLI, target_ip: str, multicast_ip: str):
    """Run network configuration tests."""
    selected_target_ip = target_ip or controller.target_ip
    selected_multicast_ip = multicast_ip or controller.multicast_ip

    if not controller.ensure_network_configuration(
        selected_target_ip, selected_multicast_ip, force=True
    ):
        raise click.ClickException("Network configuration failed.")


@cli.command("set-net")
@click.option(
    "--target-ip",
    default=None,
    help="New target device IP address. Defaults to the current setting if omitted.",
)
@click.option(
    "--multicast-ip",
    default=None,
    help="New multicast group IP address. Defaults to the current setting if omitted.",
)
@pass_controller
def set_net_command(controller: CLI, target_ip: str, multicast_ip: str):
    """Update the stored network addresses and rerun network tests."""

    updated_target_ip = target_ip or click.prompt(
        "Target IP address", default=controller.target_ip, show_default=True
    )
    updated_multicast_ip = multicast_ip or click.prompt(
        "Multicast group address", default=controller.multicast_ip, show_default=True
    )

    if not controller.ensure_network_configuration(
        updated_target_ip, updated_multicast_ip, force=True
    ):
        raise click.ClickException("Network configuration failed.")

    click.echo("Network settings updated.")


@cli.command("log")
@pass_controller
def log_command(controller: CLI):
    """Print the recent log events."""
    controller.print_last_logs()


@cli.command("help")
@pass_controller
def help_command(controller: CLI):
    """Display help information."""
    controller.help_menu()


@cli.command("cmd")
@click.pass_context
def cmd_shell(ctx):
    """Launch the interactive shell."""
    shell = CIPShell(ctx)
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        click.echo("\nExiting interactive shell...")
    finally:
        controller = ctx.obj
        if isinstance(controller, CLI):
            controller.stop_all_thread()


cli.add_command(stop_wave_command, name="stop-wave")


if __name__ == "__main__":
    cli()
