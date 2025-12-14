from pathlib import Path
from typing import Optional
from typing_extensions import Annotated

from dotenv import load_dotenv
import typer
from . import SyzVerify
from . import SyzAnalyze

app = typer.Typer(help="Syzkall/Syzbot tooling for pulling, testing, and analyzing bugs.")


# TODO: decide if this will even be apart of kexploit
@app.command()
def pull(
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name to pull bugs for')] = 'android-5-10',
):
    """Pull bugs from syzbot for a given kernel version"""
    SyzVerify.pull(syzkall_kernel)

# Probably temprorary command
@app.command()
def query(
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name to pull bugs for')] = 'android-5-10',
):
    """Query downloaded syzbot database for bugs"""
    SyzVerify.query(syzkall_kernel)

# Probably temprorary command
@app.command()
def test(
    bug_id: Annotated[str, typer.Argument(help='Bug ID to test')],
    local: Annotated[bool, typer.Option(help='Use local cuttlefish instance')] = True,
    root: Annotated[bool, typer.Option(help='Run repro as root user in VM')] = True,
    arch: Annotated[str, typer.Option(help='Architecture of kernel to test bugs on')] = 'x86_64',
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name to pull bugs for')] = 'android-5-10',
    qemu: Annotated[bool, typer.Option(help='Use QEMU VM instead of cuttlefish')]=False,
    source_image: Annotated[Path, typer.Option(help='Path to source image')] = None,
    source_disk: Annotated[Path, typer.Option(help='Path to source disk')] = None,
    outdir_name: Annotated[Optional[str], typer.Option(help='Output directory name for crash artifacts')] = "syzkall_crashes",
    dynamic_analysis: Annotated[bool, typer.Option(help='Enable GDB-based dynamic analysis')] = False,
    gdb_port: Annotated[int, typer.Option(help='GDB port for dynamic analysis')] = 1234,
):
    """Test a specific bug from syzbot"""
    SyzVerify.test(bug_id, local, arch, root, syzkall_kernel, qemu, source_disk, source_image, outdir_name, dynamic_analysis, gdb_port)

# Probably temprorary command
@app.command()
def testall(
    local: Annotated[bool, typer.Option(help='Use local cuttlefish instance')] = False,
    arch: Annotated[str, typer.Option(help='Architecture of kernel to test bugs on')] = 'x86_64',
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name to pull bugs for')] = 'android-5-10',
    qemu: Annotated[bool, typer.Option(help='Use QEMU VM instead of cuttlefish')]=False,
    source_image: Annotated[Path, typer.Option(help='Path to source image')] = None,
    source_disk: Annotated[Path, typer.Option(help='Path to source disk')] = None,
    source: Annotated[bool, typer.Option(help='Test bugs from syzbot source image')] = False,
    root: Annotated[bool, typer.Option(help='Run repro as root user in VM')] = False,
    outdir_name: Annotated[Optional[str], typer.Option(help='Output directory name for crash artifacts')] = "syzkall_crashes",
    dynamic_analysis: Annotated[bool, typer.Option(help='Enable GDB-based dynamic analysis')] = False,
    gdb_port: Annotated[int, typer.Option(help='GDB port for dynamic analysis')] = 1234,
):
    """Test all bugs from syzbot for a given kernel version"""
    SyzVerify.test_all(local, arch, syzkall_kernel, qemu, root, source_image, source_disk, source, outdir_name, dynamic_analysis, gdb_port)

# Probably temprorary command
@app.command()
def collectstats(
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name to pull bugs for')] = 'android-5-10',
    outfile: Annotated[str, typer.Option(help='Output file to write stats to')] = 'syzkall_stats',
):
    """ Collect stats on bugs from syzbot """
    SyzVerify.collect_stats(syzkall_kernel, outfile)

@app.command()
def analyze(
    bug_id: Annotated[str, typer.Argument(help='Bug ID to analyze')],
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name for bug')] = 'android-5-10',
    qemu: Annotated[bool, typer.Option(help='Use QEMU VM')] = False,
    source_image: Annotated[Path, typer.Option(help='Path to kernel image')] = None,
    source_disk: Annotated[Path, typer.Option(help='Path to disk image')] = None,
    dynamic_analysis: Annotated[bool, typer.Option(help='Enable GDB-based dynamic analysis')] = True,
    gdb_port: Annotated[int, typer.Option(help='GDB port')] = 1234,
    arch: Annotated[str, typer.Option(help='Architecture of kernel to analyze')] = 'x86_64',
    output_dir: Annotated[Optional[Path], typer.Option(help='Output directory for analysis results')] = None,
):
    """Analyze a specific bug with static and optional dynamic analysis"""
    SyzAnalyze.analyze_bug(bug_id, syzkall_kernel, qemu, source_image, source_disk, dynamic_analysis, gdb_port, arch, output_dir)
def main():
    load_dotenv()
    app()

if __name__ == "__main__":
    main()
