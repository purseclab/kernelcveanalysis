import asyncio
import subprocess
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from cuttle_types import (
    CreateInstanceRequest,
    CvdCommandMode,
    InstanceState,
    RenewLeaseRequest,
)
from fastapi import HTTPException
from typer.testing import CliRunner

from cuttle_server.api import (
    build_request_identity,
    reconcile_expired_instances_periodically,
    validate_authorization_header,
    validate_user_id_header,
)
from cuttle_server.config import (
    ConfigError,
    DEFAULT_INSTANCE_RUNTIME_ROOT,
    InstanceTemplate,
    load_settings,
)
from cuttle_server.cvd_cli import CuttlefishCli
from cuttle_server.db import InstanceDb
from cuttle_server.main import app
from cuttle_server.models import ResolvedLaunchConfig
from cuttle_server.server_manager import (
    AuthorizationError,
    CuttlefishServerManager,
    InstanceError,
)


class ConfigLoadingTests(unittest.TestCase):
    def test_load_settings_resolves_template_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_dir = root / "cf"
            bin_dir = install_dir / "bin"
            bin_dir.mkdir(parents=True)
            (bin_dir / "cvd").write_text("")
            kernel = root / "kernel"
            kernel.write_text("")
            initrd = root / "initrd.img"
            initrd.write_text("")
            app_one = root / "one.apk"
            app_one.write_text("")
            app_two = root / "two.apk"
            app_two.write_text("")
            (root / "templates").mkdir()
            (root / "cuttle_server.toml").write_text(
                'server_host = "0.0.0.0"\n'
                "server_port = 9000\n"
                'auth_token = "secret-token"\n'
                'admin_user_id = "admin"\n'
                'database_path = "data/cuttlefish.db"\n'
                "instance_timeout_sec = 123\n"
                "cvd_start_timeout_sec = 45\n"
                "base_instance_num = 4\n"
                "max_instances = 7\n"
            )
            (root / "templates" / "default.toml").write_text(
                'name = "phone"\n'
                'runtime_root = "../cf"\n'
                "cpus = 4\n"
                f'kernel_path = "{kernel}"\n'
                f'initrd_path = "{initrd}"\n'
                "selinux = false\n"
                f'apps = ["{app_one}", "{app_two}"]\n'
            )

            settings = load_settings(root)

        self.assertEqual(settings.server_host, "0.0.0.0")
        self.assertEqual(settings.server_port, 9000)
        self.assertEqual(settings.auth_token, "secret-token")
        self.assertEqual(settings.admin_user_id, "admin")
        self.assertEqual(settings.instance_timeout_sec, 123)
        self.assertEqual(settings.cvd_start_timeout_sec, 45)
        self.assertEqual(settings.reconcile_interval_sec, 30)
        self.assertEqual(settings.base_instance_num, 4)
        self.assertEqual(settings.max_instances, 7)
        self.assertEqual(settings.database_path, (root / "data/cuttlefish.db").resolve())
        self.assertEqual(settings.instance_runtime_root, DEFAULT_INSTANCE_RUNTIME_ROOT)
        template = settings.templates["phone"]
        self.assertEqual(template.cpus, 4)
        self.assertEqual(template.runtime_root, install_dir.resolve())
        self.assertEqual(template.kernel_path, kernel.resolve())
        self.assertEqual(template.initrd_path, initrd.resolve())
        self.assertEqual(template.apps, (app_one.resolve(), app_two.resolve()))
        self.assertEqual(template.command_mode, CvdCommandMode.CVD)
        self.assertEqual(template.cvd_binary, install_dir.resolve() / "bin" / "cvd")

    def test_load_settings_accepts_legacy_command_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_dir = root / "cf"
            bin_dir = install_dir / "bin"
            bin_dir.mkdir(parents=True)
            (bin_dir / "launch_cvd").write_text("")
            (bin_dir / "stop_cvd").write_text("")
            (root / "templates").mkdir()
            (root / "cuttle_server.toml").write_text(
                'auth_token = "secret-token"\n'
                'admin_user_id = "admin"\n'
                'database_path = "data/cuttlefish.db"\n'
            )
            (root / "templates" / "default.toml").write_text(
                'name = "phone"\n'
                f'runtime_root = "{install_dir}"\n'
                'command_mode = "legacy"\n'
                "cpus = 4\n"
                "selinux = false\n"
                "apps = []\n"
            )

            settings = load_settings(root)

        template = settings.templates["phone"]
        self.assertEqual(template.command_mode, CvdCommandMode.LEGACY)
        self.assertEqual(template.cvd_binary, install_dir.resolve() / "bin" / "cvd")

    def test_load_settings_validates_default_cvd_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_dir = root / "cf"
            (install_dir / "bin").mkdir(parents=True)
            (root / "templates").mkdir()
            (root / "cuttle_server.toml").write_text(
                'auth_token = "secret-token"\n'
                'admin_user_id = "admin"\n'
                'database_path = "data/cuttlefish.db"\n'
            )
            (root / "templates" / "default.toml").write_text(
                'name = "phone"\n'
                f'runtime_root = "{install_dir}"\n'
                "cpus = 4\n"
                "selinux = false\n"
                "apps = []\n"
            )

            with self.assertRaises(ConfigError) as exc_info:
                load_settings(root)

        self.assertIn("cvd binary does not exist", str(exc_info.exception))

    def test_load_settings_validates_legacy_command_mode_binaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_dir = root / "cf"
            bin_dir = install_dir / "bin"
            bin_dir.mkdir(parents=True)
            (root / "templates").mkdir()
            (root / "cuttle_server.toml").write_text(
                'auth_token = "secret-token"\n'
                'admin_user_id = "admin"\n'
                'database_path = "data/cuttlefish.db"\n'
            )
            (root / "templates" / "default.toml").write_text(
                'name = "phone"\n'
                f'runtime_root = "{install_dir}"\n'
                'command_mode = "legacy"\n'
                "cpus = 4\n"
                "selinux = false\n"
                "apps = []\n"
            )

            with self.assertRaises(ConfigError) as exc_info:
                load_settings(root)

            self.assertIn("launch_cvd binary does not exist", str(exc_info.exception))

            (bin_dir / "launch_cvd").write_text("")
            with self.assertRaises(ConfigError) as exc_info:
                load_settings(root)

        self.assertIn("stop_cvd binary does not exist", str(exc_info.exception))

    def test_load_settings_allows_omitted_kernel_and_initrd_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_dir = root / "cf"
            bin_dir = install_dir / "bin"
            bin_dir.mkdir(parents=True)
            (bin_dir / "cvd").write_text("")
            (root / "templates").mkdir()
            (root / "cuttle_server.toml").write_text(
                'auth_token = "secret-token"\n'
                'admin_user_id = "admin"\n'
                'database_path = "data/cuttlefish.db"\n'
            )
            (root / "templates" / "default.toml").write_text(
                'name = "phone"\n'
                f'runtime_root = "{install_dir}"\n'
                "cpus = 4\n"
                "selinux = false\n"
                "apps = []\n"
            )

            settings = load_settings(root)

        template = settings.templates["phone"]
        self.assertIsNone(template.kernel_path)
        self.assertIsNone(template.initrd_path)


class ServerCliTests(unittest.TestCase):
    def test_cli_starts_uvicorn_with_loaded_settings(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_dir = root / "cf"
            bin_dir = install_dir / "bin"
            bin_dir.mkdir(parents=True)
            (bin_dir / "cvd").write_text("")
            kernel = root / "kernel"
            kernel.write_text("")
            initrd = root / "initrd.img"
            initrd.write_text("")
            (root / "templates").mkdir()
            (root / "cuttle_server.toml").write_text(
                'server_host = "0.0.0.0"\n'
                "server_port = 9000\n"
                'auth_token = "secret-token"\n'
                'admin_user_id = "admin"\n'
                'database_path = "db.sqlite"\n'
            )
            (root / "templates" / "default.toml").write_text(
                'name = "phone"\n'
                f'runtime_root = "{install_dir}"\n'
                "cpus = 2\n"
                f'kernel_path = "{kernel}"\n'
                f'initrd_path = "{initrd}"\n'
                "selinux = true\n"
                "apps = []\n"
            )

            with patch("cuttle_server.main.uvicorn.run") as run:
                result = runner.invoke(app, [str(root)])

        self.assertEqual(result.exit_code, 0, result.output)
        run.assert_called_once()
        self.assertEqual(run.call_args.kwargs["host"], "0.0.0.0")
        self.assertEqual(run.call_args.kwargs["port"], 9000)

    def test_cli_flags_override_configured_bind_address(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_dir = root / "cf"
            bin_dir = install_dir / "bin"
            bin_dir.mkdir(parents=True)
            (bin_dir / "cvd").write_text("")
            kernel = root / "kernel"
            kernel.write_text("")
            initrd = root / "initrd.img"
            initrd.write_text("")
            (root / "templates").mkdir()
            (root / "cuttle_server.toml").write_text(
                'server_host = "127.0.0.1"\n'
                "server_port = 8000\n"
                'auth_token = "secret-token"\n'
                'admin_user_id = "admin"\n'
                'database_path = "db.sqlite"\n'
            )
            (root / "templates" / "default.toml").write_text(
                'name = "phone"\n'
                f'runtime_root = "{install_dir}"\n'
                "cpus = 2\n"
                f'kernel_path = "{kernel}"\n'
                f'initrd_path = "{initrd}"\n'
                "selinux = true\n"
                "apps = []\n"
            )

            with patch("cuttle_server.main.uvicorn.run") as run:
                result = runner.invoke(
                    app,
                    [str(root), "--host", "0.0.0.0", "--port", "9000"],
                )

        self.assertEqual(result.exit_code, 0, result.output)
        run.assert_called_once()
        self.assertEqual(run.call_args.kwargs["host"], "0.0.0.0")
        self.assertEqual(run.call_args.kwargs["port"], 9000)

    def test_cli_help_uses_root_command_shape(self):
        runner = CliRunner()

        result = runner.invoke(app, ["--help"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("CONFIG_DIR", result.output)
        self.assertNotIn("COMMAND [ARGS]", result.output)


class ApiAuthTests(unittest.TestCase):
    def test_validate_authorization_header_rejects_missing_token(self):
        with self.assertRaises(HTTPException) as exc_info:
            validate_authorization_header(None, "secret-token")

        self.assertEqual(exc_info.exception.status_code, 401)
        self.assertEqual(
            exc_info.exception.detail, "invalid or missing authorization token"
        )

    def test_validate_user_id_header_rejects_missing_value(self):
        with self.assertRaises(HTTPException) as exc_info:
            validate_user_id_header("  ")

        self.assertEqual(exc_info.exception.status_code, 400)
        self.assertEqual(
            exc_info.exception.detail, "missing or invalid X-User-Id header"
        )

    def test_build_request_identity_marks_admin(self):
        identity = build_request_identity(
            "Bearer secret-token",
            "admin",
            "secret-token",
            "admin",
        )

        self.assertEqual(identity.user_id, "admin")
        self.assertTrue(identity.is_admin)


class ApiBackgroundTaskTests(unittest.TestCase):
    def test_periodic_reconcile_runs_until_stop_requested(self):
        class FakeManager:
            def __init__(self) -> None:
                self.calls = 0

            def reconcile_expired_instances(self) -> None:
                self.calls += 1

        async def immediate_to_thread(func, /, *args, **kwargs):
            return func(*args, **kwargs)

        async def run_test() -> int:
            manager = FakeManager()
            stop_event = asyncio.Event()
            with patch("cuttle_server.api.asyncio.to_thread", new=immediate_to_thread):
                task = asyncio.create_task(
                    reconcile_expired_instances_periodically(
                        manager, 0.01, stop_event
                    )
                )

                await asyncio.sleep(0.035)
                stop_event.set()
                await task
            return manager.calls

        self.assertGreaterEqual(asyncio.run(run_test()), 2)

    def test_app_lifespan_starts_and_stops_reconcile_loop(self):
        fake_db = type("FakeDb", (), {"close": Mock()})()
        fake_manager = type(
            "FakeManager",
            (),
            {
                "initialize": Mock(),
                "reconcile_expired_instances": Mock(),
            },
        )()

        async def immediate_to_thread(func, /, *args, **kwargs):
            return func(*args, **kwargs)

        async def run_test() -> None:
            with patch("cuttle_server.api.asyncio.to_thread", new=immediate_to_thread):
                fake_manager.initialize()
                await asyncio.to_thread(fake_manager.reconcile_expired_instances)
                stop_event = asyncio.Event()
                task = asyncio.create_task(
                    reconcile_expired_instances_periodically(
                        fake_manager, 0.01, stop_event
                    )
                )
                try:
                    await asyncio.sleep(0.035)
                finally:
                    stop_event.set()
                    await task
                    fake_db.close()

        asyncio.run(run_test())

        fake_manager.initialize.assert_called_once()
        self.assertGreaterEqual(fake_manager.reconcile_expired_instances.call_count, 2)
        fake_db.close.assert_called_once()


class CvdCliTests(unittest.TestCase):
    def test_start_and_stop_use_instance_runtime_dir_and_android_host_env(self):
        cli = CuttlefishCli()
        with tempfile.TemporaryDirectory() as tmp:
            runtime_dir = Path(tmp) / "runtime"
            config = ResolvedLaunchConfig(
                template_name="phone",
                cpus=4,
                selinux=False,
                runtime_root=Path("/cf"),
                kernel_path=Path("/kernel"),
                initrd_path=Path("/initrd"),
                apps=[],
                cvd_binary=Path("/cf/bin/cvd"),
            )
            record = type("Record", (), {})()
            record.instance_num = 3
            record.instance_id = "inst-1"
            record.runtime_dir = runtime_dir
            record.config = config

            with patch("cuttle_server.cvd_cli.subprocess.run") as run:
                launch_result = cli.start_instance(record)
                cli.stop_instance(record)

        self.assertEqual(run.call_count, 2)
        start_call = run.call_args_list[0]
        stop_call = run.call_args_list[1]
        self.assertEqual(start_call.kwargs["cwd"], runtime_dir)
        self.assertEqual(start_call.kwargs["env"]["HOME"], str(runtime_dir))
        self.assertEqual(start_call.kwargs["env"]["ANDROID_HOST_OUT"], "/cf")
        self.assertEqual(start_call.kwargs["env"]["ANDROID_PRODUCT_OUT"], "/cf")
        self.assertNotIn("capture_output", start_call.kwargs)
        self.assertEqual(start_call.kwargs["stderr"], subprocess.STDOUT)
        self.assertEqual(start_call.kwargs["timeout"], 120)
        self.assertEqual(Path(start_call.kwargs["stdout"].name), runtime_dir / "cvd-start.log")
        self.assertEqual(stop_call.kwargs["cwd"], runtime_dir)
        self.assertEqual(stop_call.kwargs["env"]["HOME"], str(runtime_dir))
        self.assertEqual(stop_call.kwargs["env"]["ANDROID_HOST_OUT"], "/cf")
        self.assertEqual(stop_call.kwargs["env"]["ANDROID_PRODUCT_OUT"], "/cf")
        self.assertEqual(Path(stop_call.kwargs["stdout"].name), runtime_dir / "cvd-stop.log")
        self.assertEqual(launch_result.adb_port, 6522)
        self.assertEqual(
            launch_result.launch_command,
            [
                "/cf/bin/cvd",
                "start",
                "--base_instance_num=3",
                "--cpus=4",
                "--start_webrtc=true",
                "--kernel_path=/kernel",
                "--initramfs_path=/initrd",
                "--daemon",
                "--report_anonymous_usage_stats=n",
                "--extra_kernel_cmdline=androidboot.selinux=permissive",
            ],
        )
        self.assertEqual(stop_call.args[0], ["/cf/bin/cvd", "stop"])

    def test_legacy_mode_uses_launch_and_stop_cvd_binaries(self):
        cli = CuttlefishCli()
        with tempfile.TemporaryDirectory() as tmp:
            runtime_dir = Path(tmp) / "runtime"
            config = ResolvedLaunchConfig(
                template_name="phone",
                cpus=4,
                selinux=True,
                runtime_root=Path("/cf"),
                kernel_path=Path("/kernel"),
                initrd_path=Path("/initrd"),
                apps=[],
                command_mode=CvdCommandMode.LEGACY,
                cvd_binary=Path("/cf/bin/cvd"),
            )
            record = type("Record", (), {})()
            record.instance_num = 3
            record.instance_id = "inst-1"
            record.runtime_dir = runtime_dir
            record.config = config

            with patch("cuttle_server.cvd_cli.subprocess.run") as run:
                launch_result = cli.start_instance(record)
                cli.stop_instance(record)

        self.assertEqual(
            launch_result.launch_command,
            [
                "/cf/bin/launch_cvd",
                "--base_instance_num=3",
                "--cpus=4",
                "--start_webrtc=true",
                "--kernel_path=/kernel",
                "--initramfs_path=/initrd",
                "--daemon",
                "--report_anonymous_usage_stats=n",
            ],
        )
        self.assertEqual(run.call_args_list[1].args[0], ["/cf/bin/stop_cvd"])

    def test_start_omits_kernel_and_initrd_args_when_paths_are_unset(self):
        cli = CuttlefishCli()
        config = ResolvedLaunchConfig(
            template_name="phone",
            cpus=4,
            selinux=True,
            runtime_root=Path("/cf"),
            kernel_path=None,
            initrd_path=None,
            apps=[],
            cvd_binary=Path("/cf/bin/cvd"),
        )
        record = type("Record", (), {})()
        record.instance_num = 3
        record.runtime_dir = Path("/runtime")
        record.config = config

        command = cli._build_start_command(record)

        self.assertEqual(
            command,
            [
                "/cf/bin/cvd",
                "start",
                "--base_instance_num=3",
                "--cpus=4",
                "--start_webrtc=true",
                "--daemon",
                "--report_anonymous_usage_stats=n",
            ],
        )

    def test_start_includes_only_configured_kernel_or_initrd_args(self):
        cli = CuttlefishCli()
        record = type("Record", (), {})()
        record.instance_num = 3
        record.runtime_dir = Path("/runtime")
        record.config = ResolvedLaunchConfig(
            template_name="phone",
            cpus=4,
            selinux=True,
            runtime_root=Path("/cf"),
            kernel_path=Path("/kernel"),
            initrd_path=None,
            apps=[],
            cvd_binary=Path("/cf/bin/cvd"),
        )

        kernel_only_command = cli._build_start_command(record)

        record.config = record.config.model_copy(
            update={"kernel_path": None, "initrd_path": Path("/initrd")}
        )
        initrd_only_command = cli._build_start_command(record)

        self.assertIn("--kernel_path=/kernel", kernel_only_command)
        self.assertNotIn("--initramfs_path=/initrd", kernel_only_command)
        self.assertNotIn("--kernel_path=/kernel", initrd_only_command)
        self.assertIn("--initramfs_path=/initrd", initrd_only_command)

    def test_failed_start_logs_stdout_and_stderr(self):
        cli = CuttlefishCli()
        with tempfile.TemporaryDirectory() as tmp:
            runtime_dir = Path(tmp) / "runtime"
            config = ResolvedLaunchConfig(
                template_name="phone",
                cpus=4,
                selinux=False,
                runtime_root=Path("/cf"),
                kernel_path=Path("/kernel"),
                initrd_path=Path("/initrd"),
                apps=[],
                cvd_binary=Path("/cf/bin/cvd"),
            )
            record = type("Record", (), {})()
            record.instance_num = 3
            record.instance_id = "inst-1"
            record.runtime_dir = runtime_dir
            record.config = config
            error = subprocess.CalledProcessError(
                1,
                ["/cf/bin/cvd", "start"],
            )

            def fail_start(*args, **kwargs):
                kwargs["stdout"].write("launch stdout\nlaunch stderr\n")
                raise error

            with self.assertLogs("cuttle_server.cvd_cli", level="ERROR") as logs:
                with patch(
                    "cuttle_server.cvd_cli.subprocess.run",
                    side_effect=fail_start,
                ):
                    with self.assertRaises(RuntimeError) as exc_info:
                        cli.start_instance(record)

        joined_logs = "\n".join(logs.output)
        self.assertIn("$ /cf/bin/cvd start", joined_logs)
        self.assertIn("launch stdout", joined_logs)
        self.assertIn("launch stderr", joined_logs)
        self.assertIn("$ /cf/bin/cvd start", str(exc_info.exception))
        self.assertIn("launch stdout", str(exc_info.exception))

    def test_start_timeout_reports_log_tail(self):
        cli = CuttlefishCli(start_timeout_sec=5)
        with tempfile.TemporaryDirectory() as tmp:
            runtime_dir = Path(tmp) / "runtime"
            config = ResolvedLaunchConfig(
                template_name="phone",
                cpus=4,
                selinux=False,
                runtime_root=Path("/cf"),
                kernel_path=Path("/kernel"),
                initrd_path=Path("/initrd"),
                apps=[],
                cvd_binary=Path("/cf/bin/cvd"),
            )
            record = type("Record", (), {})()
            record.instance_num = 3
            record.instance_id = "inst-1"
            record.runtime_dir = runtime_dir
            record.config = config

            def timeout(*args, **kwargs):
                kwargs["stdout"].write("still booting\n")
                raise subprocess.TimeoutExpired(args[0], 5)

            with self.assertLogs("cuttle_server.cvd_cli", level="ERROR"):
                with patch("cuttle_server.cvd_cli.subprocess.run", side_effect=timeout):
                    with self.assertRaises(RuntimeError) as exc_info:
                        cli.start_instance(record)

        self.assertIn("timed out after 5s", str(exc_info.exception))
        self.assertIn("still booting", str(exc_info.exception))


class FakeCli:
    def __init__(self) -> None:
        self.stop_calls: list[str] = []

    def build_start_command(self, record):
        return ["launch", record.instance_id]

    def start_instance(self, record):
        record.runtime_dir.mkdir(parents=True, exist_ok=True)
        (record.runtime_dir / "cvd-start.log").write_text("started\n")
        return type(
                "LaunchResult",
                (),
                {
                    "launch_command": self.build_start_command(record),
                    "adb_port": 6520 + record.instance_num - 1,
                    "adb_serial": None,
                "webrtc_port": None,
            },
        )()

    def stop_instance(self, record):
        self.stop_calls.append(record.instance_id)
        record.runtime_dir.mkdir(parents=True, exist_ok=True)
        (record.runtime_dir / "cvd-stop.log").write_text("stopped\n")


class FakeAppLoader:
    def __init__(self) -> None:
        self.loaded_instance_ids: list[str] = []

    def load_apps(self, record) -> None:
        self.loaded_instance_ids.append(record.instance_id)


class FailingAppLoader:
    def load_apps(self, record) -> None:
        raise RuntimeError("install failed")


class ServerManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.db = InstanceDb(self.root / "db.sqlite")
        self.cli = FakeCli()
        self.app_loader = FakeAppLoader()
        self.settings = type(
            "Settings",
            (),
            {
                "server_host": "127.0.0.1",
                "server_port": 8000,
                "database_path": self.root / "db.sqlite",
                "instance_runtime_root": self.root / "instances",
                "instance_timeout_sec": 60,
                "cvd_start_timeout_sec": 120,
                "reconcile_interval_sec": 30,
                "base_instance_num": 0,
                "max_instances": 10,
                "admin_user_id": "admin",
                "templates": {
                    "phone": InstanceTemplate(
                        name="phone",
                        runtime_root=Path("/cf"),
                        command_mode=CvdCommandMode.CVD,
                        cvd_binary=Path("/cf/bin/cvd"),
                        cpus=2,
                        kernel_path=Path("/kernel"),
                        initrd_path=Path("/initrd"),
                        selinux=True,
                        apps=(Path("/app-one.apk"), Path("/app-two.apk")),
                    )
                },
            },
        )()
        self.manager = CuttlefishServerManager(
            self.settings,
            self.db,
            self.cli,
            self.app_loader,
        )
        self.manager.initialize()

    def tearDown(self) -> None:
        self.db.close()
        self.tempdir.cleanup()

    def test_unnamed_instances_fall_back_to_instance_id(self):
        created = self.manager.create_instance(
            "alice",
            CreateInstanceRequest(template_name="phone"),
        ).instance

        self.assertEqual(created.instance_name, created.instance_id)
        self.assertEqual(created.adb_port, 6520)
        self.assertTrue(created.load_apps)
        self.assertEqual(created.command_mode, CvdCommandMode.CVD)
        record = self.db.get(created.instance_id)
        assert record is not None
        self.assertIsNone(record.instance_name)
        self.assertEqual(record.adb_port, 6520)
        self.assertTrue(record.config.load_apps)
        self.assertEqual(record.config.command_mode, CvdCommandMode.CVD)
        self.assertEqual(record.runtime_dir.parent, self.root / "instances")
        self.assertEqual(len(record.runtime_dir.name), 32)
        self.assertEqual(record.launch_command, ["launch", created.instance_id])

    def test_base_instance_num_offsets_allocated_slots(self):
        self.settings.base_instance_num = 5

        created = self.manager.create_instance(
            "alice",
            CreateInstanceRequest(template_name="phone"),
        ).instance

        self.assertEqual(created.instance_num, 6)
        self.assertEqual(created.adb_port, 6525)
        record = self.db.get(created.instance_id)
        assert record is not None
        self.assertEqual(record.instance_num, 6)

    def test_capacity_uses_offset_managed_range(self):
        self.settings.base_instance_num = 5
        self.settings.max_instances = 2
        self.manager.create_instance(
            "alice",
            CreateInstanceRequest(template_name="phone", instance_name="one"),
        )
        self.manager.create_instance(
            "alice",
            CreateInstanceRequest(template_name="phone", instance_name="two"),
        )

        with self.assertRaises(InstanceError) as exc_info:
            self.manager.create_instance(
                "alice",
                CreateInstanceRequest(template_name="phone", instance_name="three"),
            )

        self.assertIn("managed range is 6-7", str(exc_info.exception))

    def test_app_loading_runs_by_default(self):
        created = self.manager.create_instance(
            "alice",
            CreateInstanceRequest(template_name="phone"),
        ).instance

        self.assertEqual(self.app_loader.loaded_instance_ids, [created.instance_id])

    def test_load_apps_can_be_disabled_per_request(self):
        created = self.manager.create_instance(
            "alice",
            CreateInstanceRequest(
                template_name="phone",
                overrides={"load_apps": False},
            ),
        ).instance

        self.assertEqual(self.app_loader.loaded_instance_ids, [])
        self.assertFalse(created.load_apps)
        record = self.db.get(created.instance_id)
        assert record is not None
        self.assertFalse(record.config.load_apps)

    def test_failed_app_loading_crashes_instance_and_stops_it(self):
        manager = CuttlefishServerManager(
            self.settings,
            self.db,
            self.cli,
            FailingAppLoader(),
        )

        with self.assertRaises(InstanceError) as exc_info:
            manager.create_instance("alice", CreateInstanceRequest(template_name="phone"))

        self.assertIn("failed to load apps", str(exc_info.exception))
        crashed_records = [record for record in self.db.list_instances("alice")]
        self.assertEqual(len(crashed_records), 1)
        self.assertEqual(crashed_records[0].state, InstanceState.CRASHED)
        self.assertIn("install failed", crashed_records[0].failure_reason or "")
        self.assertEqual(self.cli.stop_calls, [crashed_records[0].instance_id])
        self.assertFalse(crashed_records[0].runtime_dir.exists())

    def test_explicit_names_are_unique_per_user_but_shared_across_users(self):
        self.manager.create_instance(
            "alice",
            CreateInstanceRequest(template_name="phone", instance_name="demo"),
        )
        self.manager.create_instance(
            "bob",
            CreateInstanceRequest(template_name="phone", instance_name="demo"),
        )
        with self.assertRaises(InstanceError):
            self.manager.create_instance(
                "alice",
                CreateInstanceRequest(template_name="phone", instance_name="demo"),
            )

    def test_list_and_get_enforce_user_visibility(self):
        alice_instance = self.manager.create_instance(
            "alice",
            CreateInstanceRequest(template_name="phone", instance_name="alice-vm"),
        ).instance
        bob_instance = self.manager.create_instance(
            "bob",
            CreateInstanceRequest(template_name="phone", instance_name="bob-vm"),
        ).instance

        alice_list = self.manager.list_instances("alice", is_admin=False)
        admin_list = self.manager.list_instances("admin", is_admin=True)

        self.assertEqual([inst.owner_id for inst in alice_list.instances], ["alice"])
        self.assertEqual(len(admin_list.instances), 2)

        with self.assertRaises(AuthorizationError):
            self.manager.get_instance("alice", is_admin=False, instance_id=bob_instance.instance_id)

        admin_view = self.manager.get_instance(
            "admin", is_admin=True, instance_id=alice_instance.instance_id
        )
        self.assertEqual(admin_view.owner_id, "alice")

    def test_get_instance_logs_returns_runtime_logs(self):
        created = self.manager.create_instance(
            "alice",
            CreateInstanceRequest(template_name="phone", instance_name="demo"),
        ).instance

        logs = self.manager.get_instance_logs(
            "alice",
            is_admin=False,
            instance_id=created.instance_id,
        )

        self.assertEqual(logs.instance_name, "demo")
        self.assertEqual(logs.state, InstanceState.ACTIVE)
        self.assertIn("started", logs.start_log)
        self.assertEqual(logs.launch_command, ["launch", created.instance_id])

    def test_get_instance_logs_enforces_visibility(self):
        bob_instance = self.manager.create_instance(
            "bob",
            CreateInstanceRequest(template_name="phone", instance_name="bob-vm"),
        ).instance

        with self.assertRaises(AuthorizationError):
            self.manager.get_instance_logs(
                "alice",
                is_admin=False,
                instance_id=bob_instance.instance_id,
            )

    def test_stop_by_name_uses_instance_id_for_unnamed_instances(self):
        created = self.manager.create_instance(
            "alice",
            CreateInstanceRequest(template_name="phone"),
        ).instance

        stopped = self.manager.stop_instance_by_name(
            "alice", is_admin=False, instance_name=created.instance_id
        )

        self.assertEqual(stopped.state, InstanceState.STOPPED)
        self.assertFalse(created.runtime_dir.exists())

    def test_stop_and_expire_remove_runtime_dirs(self):
        created = self.manager.create_instance(
            "alice",
            CreateInstanceRequest(template_name="phone", instance_name="demo"),
        ).instance
        runtime_dir = created.runtime_dir
        self.assertTrue(runtime_dir.exists())

        stopped = self.manager.stop_instance(
            "alice", is_admin=False, instance_id=created.instance_id
        )
        self.assertEqual(stopped.state, InstanceState.STOPPED)
        self.assertFalse(runtime_dir.exists())

        created_two = self.manager.create_instance(
            "alice",
            CreateInstanceRequest(template_name="phone", instance_name="demo"),
        ).instance
        record = self.db.get(created_two.instance_id)
        assert record is not None
        record.expires_at = record.expires_at - timedelta(seconds=120)
        self.db.upsert(record)

        self.manager.reconcile_expired_instances()

        expired = self.db.get(created_two.instance_id)
        assert expired is not None
        self.assertEqual(expired.state, InstanceState.EXPIRED)
        self.assertFalse(created_two.runtime_dir.exists())

    def test_zero_timeout_in_config_disables_expiration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_dir = root / "cf"
            bin_dir = install_dir / "bin"
            bin_dir.mkdir(parents=True)
            (bin_dir / "cvd").write_text("")
            kernel = root / "kernel"
            kernel.write_text("")
            initrd = root / "initrd.img"
            initrd.write_text("")
            (root / "templates").mkdir()
            (root / "cuttle_server.toml").write_text(
                'auth_token = "secret-token"\n'
                'admin_user_id = "admin"\n'
                'database_path = "data/cuttlefish.db"\n'
                "instance_timeout_sec = 0\n"
            )
            (root / "templates" / "default.toml").write_text(
                'name = "phone"\n'
                f'runtime_root = "{install_dir}"\n'
                "cpus = 2\n"
                f'kernel_path = "{kernel}"\n'
                f'initrd_path = "{initrd}"\n'
                "selinux = true\n"
                "apps = []\n"
            )

            settings = load_settings(root)

        self.assertIsNone(settings.instance_timeout_sec)

    def test_disabled_global_timeout_leaves_instance_unexpired(self):
        self.settings.instance_timeout_sec = None

        created = self.manager.create_instance(
            "alice",
            CreateInstanceRequest(template_name="phone", instance_name="demo"),
        ).instance
        self.assertIsNone(created.expires_at)

        self.manager.reconcile_expired_instances()

        record = self.db.get(created.instance_id)
        assert record is not None
        self.assertEqual(record.state, InstanceState.ACTIVE)
        self.assertIsNone(record.expires_at)

    def test_renew_without_timeout_keeps_disabled_global_expiration(self):
        self.settings.instance_timeout_sec = None
        created = self.manager.create_instance(
            "alice",
            CreateInstanceRequest(template_name="phone", instance_name="demo"),
        ).instance

        renewed = self.manager.renew_lease(
            "alice",
            is_admin=False,
            instance_id=created.instance_id,
            request=RenewLeaseRequest(),
        )

        self.assertIsNone(renewed.expires_at)
