import logging
from pathlib import Path

import typer
from dotenv import load_dotenv
from kexploit_agent import Model

from .bug_hunter.bug_hunter import BugHunter

app = typer.Typer(
    add_completion=False,
    help="Analyze a challenge directory for APK/native-library version clues and known CVEs.",
)


@app.command()
def analyze(
    input_dir: Path = typer.Option(
        "apps",
        "--input-dir",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        resolve_path=True,
        help="Directory containing challenge APKs and related artifacts.",
    ),
    output_dir: Path = typer.Option(
        "findings",
        "--output-dir",
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
        help="Directory for output reports, pocs, and exploits.",
    ),
    model: Model = typer.Option(
        "--model",
        help="LangChain model identifier to use for the agent.",
        default_factory=lambda: Model.GPT_5_1,
    ),
) -> None:
    load_dotenv()
    logging.basicConfig(level=logging.WARNING)

    output_dir.mkdir(parents=True, exist_ok=True)

    # run the bug hunter
    bug_hunter = BugHunter(
        input_dir=input_dir,
        output_dir=output_dir,
        model=model,
    )

    bug_hunter.run()

    # run the exploit writer

    # run the exploit chainer


def main():
    app()


if __name__ == "__main__":
    main()
