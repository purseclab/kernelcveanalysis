import os
from logging import getLogger
from pathlib import Path
from secrets import token_hex

from kexploit_agent import Agent, DockerSandboxProvider, Model, MountInfo
from kexploit_agent.agent import BaseTool
from langchain_core.messages import HumanMessage
from langchain_tavily import TavilySearch

from .prompts import BUG_HUNTER_PROMPT

logger = getLogger(__name__)


class BugHunter:
    tools: list[BaseTool]

    def __init__(
        self,
        input_dir: Path,
        output_dir: Path,
        model: Model,
    ) -> None:
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.model = model

        self.input_mount = MountInfo(
            src_folder=input_dir,
            name="apps",
            description="Folder containing app APKs to be analyzed",
            writable=False,
        )

        self.output_mount = MountInfo(
            src_folder=output_dir,
            name="output",
            description="Folder where output reports and POCs should be written.",
            writable=True,
        )

        self.sandbox = None

        if os.environ.get("TAVILY_API_KEY"):
            self.tools = [TavilySearch()]
        else:
            raise ValueError(
                "TAVILY_API_KEY not set, TavilySearch tool will not be available."
            )

    def _make_agent(self, name: str) -> Agent:
        assert self.sandbox is not None, (
            "sandbox not started, can't create bug hunter agent"
        )
        return Agent(
            model=self.model.create_model(),
            tools=self.tools,
            system_prompt=BUG_HUNTER_PROMPT,
            name=name,
            sandbox=self.sandbox,
        )

    def run(self) -> None:
        with DockerSandboxProvider.get().create_instance(
            mounts=[
                self.input_mount,
                self.output_mount,
                MountInfo.new_llm_workdir(
                    "workdir",
                    "A writable folder you can use as a workspace for analysis. Do not place final reports here, only use if you need to extract files, write test scripts, etc.",
                ),
            ],
            name=f"cuttleagent-analysis-{token_hex(4)}",
        ) as sandbox:
            self.sandbox = sandbox

            for app in self.input_dir.iterdir():
                if app.is_file():
                    self.analyze_app(app.name)

            self.write_final_report()

        self.sandbox = None

    def analyze_app(self, app_name: str):
        container_app_path = Path(self.input_mount.dst_path()) / app_name
        results_folder_name = ".".join(app_name.split(".")[:-1])
        output_path = Path(self.output_mount.dst_path()) / results_folder_name

        if (self.output_dir / results_folder_name).exists():
            logger.info(f"Skipping app {app_name}, results folder already exists")
            return

        user_prompt = f"""Analyze only this APK: {container_app_path}

        Tasks:
        - determine package name and app version
        - enumerate bundled .so files
        - inspect each .so one at a time
        - identify likely library names and version clues
        - research likely known CVEs
          - Even if there are no .so or 3rd party dependencies you can find,
            still search for info about the app itself to determine if any CVEs are present.
        - write findings into {output_path / "REPORT.md"}
        - write pocs into {output_path / "POCS.md"}

        Do not analyze other apps in this run.
        Do not write REPORT.md in this run.

        """
        inputs = {"messages": [HumanMessage(content=user_prompt)]}

        self._make_agent("apk_analysis_agent").invoke(inputs)

    def write_final_report(self):
        output_path = self.output_mount.dst_path()
        user_prompt = f"""
        Read all per-app reports in {output_path} (NOTE: they will be inside the subfolders in this folder) and write REPORT.md in {output_path}.

        Tasks:
        - summarize highest-confidence findings
        - note repeated vulnerable components
        - note cross-app observations
        - do not redo raw APK analysis
        - note as many possible chains as you can. (For example an app may call another app with an intent).
        """

        inputs = {"messages": [HumanMessage(content=user_prompt)]}

        self._make_agent("final_report_agent").invoke(inputs)
