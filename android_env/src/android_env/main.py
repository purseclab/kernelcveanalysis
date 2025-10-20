from typing_extensions import Annotated
from pathlib import Path

import typer

from .seccomp import dump_seccomp
from .selinux import dump_selinux_info, diff_selinux_info

app = typer.Typer()

selinux_commands = typer.Typer()

app.add_typer(selinux_commands, name='selinux')

@app.command(help='Dump allowed syscalls by seccomp policy on android vm.')
def seccomp(
    json_file: Annotated[Path, typer.Argument(help='Path to json file where information about allowed syscalls will be saved.')],
):
    dump_seccomp(json_file)

@selinux_commands.command('dump', help='Dump information about reachable services based on selinux policy.')
def selinux_dump(
    setype: Annotated[str, typer.Argument(help='Selinux type to dump info about.')],
):
    dump_selinux_info(setype)

@selinux_commands.command('diff', help='Diff information about 2 different selinux types.')
def selinux_diff(
    setype1: Annotated[str, typer.Argument(help='First selinux type to diff,')],
    setype2: Annotated[str, typer.Argument(help='Second selinux type to diff,')],
):
    diff_selinux_info(setype1, setype2)

# TEMP command
@app.command()
def codeql_test():
    from .codeql import codeql_test
    codeql_test()

def main():
    app()

if __name__ == '__main__':
    main()
