import asyncio
import json
import os
import platform
import sqlite3
import subprocess
import tempfile
import time
import unittest
from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from cuttle_types import (
    CreateInstanceRequest,
    CreateSnapshotRequest,
    CuttlefishBackendKind,
    CvdCommandMode,
    InstanceState,
    RenewLeaseRequest,
    RestoreSnapshotRequest,
    SnapshotState,
)
from cuttle_server.backends import (
    BackendLogs,
    BackendReconcileFailure,
    HostCuttlefishBackend,
    LaunchResult,
)
from fastapi import HTTPException
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from cuttle_server.api import (
    build_request_identity,
    create_app,
    reconcile_expired_instances_periodically,
    validate_authorization_header,
    validate_user_id_header,
)
from cuttle_server.config import (
    ConfigError,
    CuttlefishSettings,
    InstanceTemplate,
    load_settings,
)
from cuttle_server.db import InstanceDb
from cuttle_server.main import app
from cuttle_server.models import InstanceRecord, ResolvedLaunchConfig, utc_now
from cuttle_server.server_manager import (
    AuthorizationError,
    CuttlefishServerManager,
    InstanceError,
    NotFoundError,
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
        self.assertEqual(settings.instance_runtime_root, Path("/tmp/cvd"))
        template = settings.templates["phone"]
        self.assertEqual(template.cpus, 4)
        self.assertEqual(template.runtime_root, install_dir.resolve())
        self.assertEqual(template.kernel_path, kernel.resolve())
        self.assertEqual(template.initrd_path, initrd.resolve())
        self.assertEqual(template.apps, (app_one.resolve(), app_two.resolve()))
        self.assertEqual(template.command_mode, CvdCommandMode.CVD)
        self.assertEqual(template.backend, CuttlefishBackendKind.HOST)
        self.assertIsNone(template.docker_image)
        self.assertEqual(template.cvd_binary, install_dir.resolve() / "bin" / "cvd")

    def test_load_settings_resolves_docker_image_override_and_default(self):
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
                'docker_image = "cuttlefish:default"\n'
            )
            (root / "templates" / "default.toml").write_text(
                'name = "default"\n'
                f'runtime_root = "{install_dir}"\n'
                'backend = "docker"\n'
                "cpus = 4\n"
                "selinux = false\n"
            )
            (root / "templates" / "override.toml").write_text(
                'name = "override"\n'
                f'runtime_root = "{install_dir}"\n'
                'backend = "docker"\n'
                'docker_image = "cuttlefish:override"\n'
                "cpus = 4\n"
                "selinux = false\n"
            )

            settings = load_settings(root)

        self.assertEqual(
            settings.templates["default"].docker_image,
            "cuttlefish:default",
        )
        self.assertEqual(
            settings.templates["override"].docker_image,
            "cuttlefish:override",
        )

    def test_load_settings_rejects_docker_template_without_image(self):
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
                'backend = "docker"\n'
                "cpus = 4\n"
                "selinux = false\n"
            )

            with self.assertRaises(ConfigError) as exc_info:
                load_settings(root)

        self.assertIn("defines docker_image", str(exc_info.exception))

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

    def _write_snapshot_config(
        self,
        root: Path,
        *,
        template_extra: str,
        main_extra: str = "",
        snapshot_util: bool = True,
    ) -> Path:
        install_dir = root / "cf"
        bin_dir = install_dir / "bin"
        bin_dir.mkdir(parents=True)
        (bin_dir / "launch_cvd").write_text("")
        (bin_dir / "stop_cvd").write_text("")
        if snapshot_util:
            (bin_dir / "snapshot_util_cvd").write_text("")
        (root / "templates").mkdir()
        (root / "cuttle_server.toml").write_text(
            'auth_token = "secret-token"\n'
            'admin_user_id = "admin"\n'
            'database_path = "data/cuttlefish.db"\n'
            f"{main_extra}"
        )
        (root / "templates" / "default.toml").write_text(
            'name = "phone"\n'
            f'runtime_root = "{install_dir}"\n'
            "cpus = 4\n"
            "selinux = false\n"
            f"{template_extra}"
        )
        return root

    def test_load_settings_reads_snapshot_support_and_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._write_snapshot_config(
                Path(tmp),
                template_extra='command_mode = "legacy"\nsnapshot_supported = true\n',
                main_extra='snapshot_root = "/srv/snapshots"\n',
            )
            settings = load_settings(root)

        self.assertTrue(settings.templates["phone"].snapshot_supported)
        self.assertEqual(settings.snapshot_root, Path("/srv/snapshots"))

    def test_load_settings_defaults_to_no_snapshots_and_standard_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._write_snapshot_config(
                Path(tmp), template_extra='command_mode = "legacy"\n'
            )
            settings = load_settings(root)

        self.assertFalse(settings.templates["phone"].snapshot_supported)
        self.assertEqual(settings.snapshot_root, Path("/var/lib/cuttlefish_snapshots"))

    def test_load_settings_rejects_snapshot_support_without_legacy_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._write_snapshot_config(
                Path(tmp), template_extra="snapshot_supported = true\n"
            )
            (root / "cf" / "bin" / "cvd").write_text("")
            with self.assertRaisesRegex(ConfigError, 'command_mode = "legacy"'):
                load_settings(root)

    def test_load_settings_rejects_snapshot_support_for_docker_backend(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._write_snapshot_config(
                Path(tmp),
                template_extra=(
                    'command_mode = "legacy"\nbackend = "docker"\n'
                    'docker_image = "cuttlefish-host:latest"\n'
                    "snapshot_supported = true\n"
                ),
            )
            with self.assertRaisesRegex(ConfigError, "only implemented for the host"):
                load_settings(root)

    def test_load_settings_rejects_snapshot_support_without_snapshot_util(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._write_snapshot_config(
                Path(tmp),
                template_extra='command_mode = "legacy"\nsnapshot_supported = true\n',
                snapshot_util=False,
            )
            with self.assertRaisesRegex(ConfigError, "snapshot_util_cvd"):
                load_settings(root)

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


class DatabaseMigrationTests(unittest.TestCase):
    def test_legacy_record_defaults_to_host_backend_and_adds_runtime_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            database_path = Path(tmp) / "instances.sqlite"
            connection = sqlite3.connect(database_path)
            connection.executescript(
                """
                CREATE TABLE instances (
                    instance_id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    instance_name TEXT,
                    state TEXT NOT NULL,
                    instance_num INTEGER NOT NULL,
                    config_json TEXT NOT NULL,
                    runtime_dir TEXT NOT NULL,
                    launch_command_json TEXT NOT NULL,
                    adb_port INTEGER,
                    adb_serial TEXT,
                    webrtc_port INTEGER,
                    expires_at TEXT,
                    failure_reason TEXT
                );
                """
            )
            legacy_config = {
                "template_name": "phone",
                "cpus": 2,
                "selinux": True,
                "runtime_root": "/cf",
                "kernel_path": None,
                "initrd_path": None,
                "apps": [],
                "load_apps": True,
                "command_mode": "cvd",
                "cvd_binary": "/cf/bin/cvd",
            }
            connection.execute(
                """
                INSERT INTO instances VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    "legacy",
                    "alice",
                    None,
                    "active",
                    1,
                    json.dumps(legacy_config),
                    "/tmp/cvd/legacy",
                    "[]",
                    6520,
                    None,
                    None,
                    None,
                    None,
                ),
            )
            connection.commit()
            connection.close()

            database = InstanceDb(database_path)
            database.initialize()
            record = database.get("legacy")
            database.close()

        assert record is not None
        self.assertEqual(record.config.backend, CuttlefishBackendKind.HOST)
        self.assertIsNone(record.config.docker_image)
        self.assertFalse(record.config.unmanaged)
        self.assertIsNone(record.backend_runtime_id)


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


class HostCuttlefishBackendTests(unittest.TestCase):
    @staticmethod
    def _create_tap_interfaces(sys_class_net_dir: Path, instance_num: int) -> None:
        suffix = f"{instance_num:02d}"
        for prefix in ("cvd-etap", "cvd-mtap", "cvd-wtap", "cvd-wifiap"):
            (sys_class_net_dir / f"{prefix}-{suffix}").mkdir(parents=True)

    def test_start_and_stop_use_instance_runtime_dir_and_android_host_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_class_net_dir = root / "sys-class-net"
            self._create_tap_interfaces(sys_class_net_dir, 3)
            cli = HostCuttlefishBackend(sys_class_net_dir=sys_class_net_dir)
            runtime_dir = root / "runtime"
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

            with patch("cuttle_server.backends.host.subprocess.run") as run:
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
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_class_net_dir = root / "sys-class-net"
            self._create_tap_interfaces(sys_class_net_dir, 3)
            cli = HostCuttlefishBackend(sys_class_net_dir=sys_class_net_dir)
            runtime_dir = root / "runtime"
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

            with patch("cuttle_server.backends.host.subprocess.run") as run:
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
        cli = HostCuttlefishBackend()
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
        cli = HostCuttlefishBackend()
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
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_class_net_dir = root / "sys-class-net"
            self._create_tap_interfaces(sys_class_net_dir, 3)
            cli = HostCuttlefishBackend(sys_class_net_dir=sys_class_net_dir)
            runtime_dir = root / "runtime"
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

            with self.assertLogs("cuttle_server.backends.host", level="ERROR") as logs:
                with patch(
                    "cuttle_server.backends.host.subprocess.run",
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
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_class_net_dir = root / "sys-class-net"
            self._create_tap_interfaces(sys_class_net_dir, 3)
            cli = HostCuttlefishBackend(
                start_timeout_sec=5,
                sys_class_net_dir=sys_class_net_dir,
            )
            runtime_dir = root / "runtime"
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

            with self.assertLogs("cuttle_server.backends.host", level="ERROR"):
                with patch(
                    "cuttle_server.backends.host.subprocess.run",
                    side_effect=timeout,
                ):
                    with self.assertRaises(RuntimeError) as exc_info:
                        cli.start_instance(record)

        self.assertIn("timed out after 5s", str(exc_info.exception))
        self.assertIn("still booting", str(exc_info.exception))

    def test_start_rejects_missing_tap_interfaces_before_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_class_net_dir = root / "sys-class-net"
            self._create_tap_interfaces(sys_class_net_dir, 13)
            (sys_class_net_dir / "cvd-mtap-13").rmdir()
            (sys_class_net_dir / "cvd-wifiap-13").rmdir()
            cli = HostCuttlefishBackend(sys_class_net_dir=sys_class_net_dir)
            runtime_dir = root / "runtime"
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
            record.instance_num = 13
            record.runtime_dir = runtime_dir
            record.config = config

            with patch("cuttle_server.backends.host.subprocess.run") as run:
                with self.assertRaises(RuntimeError) as exc_info:
                    cli.start_instance(record)

            error = str(exc_info.exception)
            self.assertIn("Cuttlefish instance 13", error)
            self.assertIn("cvd-mtap-13", error)
            self.assertIn("cvd-wifiap-13", error)
            self.assertIn("num_cvd_accounts", error)
            self.assertFalse(runtime_dir.exists())
            run.assert_not_called()

    def test_read_logs_includes_internal_cuttlefish_logs(self):
        cli = HostCuttlefishBackend()
        with tempfile.TemporaryDirectory() as tmp:
            record = type("Record", (), {})()
            record.instance_num = 3
            record.runtime_dir = Path(tmp) / "runtime"
            paths = cli.log_paths(record)
            for path, contents in (
                (paths.start_log, "start\n"),
                (paths.stop_log, "stop\n"),
                (paths.kernel_log, "kernel\n"),
                (paths.launcher_log, "launcher\n"),
                (paths.logcat, "logcat\n"),
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)

            logs = cli.read_logs(record)

        self.assertEqual(logs.kernel_log, "kernel\n")
        self.assertEqual(logs.launcher_log, "launcher\n")
        self.assertEqual(logs.logcat, "logcat\n")


class FakeBackend:
    def __init__(
        self,
        kind: CuttlefishBackendKind = CuttlefishBackendKind.HOST,
    ) -> None:
        self.kind = kind
        self.start_calls: list[str] = []
        self.stop_calls: list[str] = []
        self.start_error: RuntimeError | None = None
        self.stop_error: RuntimeError | None = None
        # Snapshot directory passed to each start (None for a normal start).
        self.start_snapshot_dirs: list[Path | None] = []
        self.snapshot_calls: list[tuple[str, Path]] = []
        self.snapshot_error: RuntimeError | None = None
        self.fingerprint = "fingerprint-1"

    def build_start_command(
        self, record: InstanceRecord, *, snapshot_dir: Path | None = None
    ) -> list[str]:
        command = ["launch", record.instance_id]
        if record.config.snapshot_compatible:
            command.append("--snapshots")
        if snapshot_dir is not None:
            command.append(f"--snapshot_path={snapshot_dir}")
        return command

    def take_snapshot(self, record: InstanceRecord, snapshot_dir: Path) -> None:
        self.snapshot_calls.append((record.instance_id, snapshot_dir))
        if self.snapshot_error is not None:
            raise self.snapshot_error
        snapshot_dir.mkdir(parents=True)
        (snapshot_dir / "memory").write_bytes(b"x" * 4096)

    def host_tools_fingerprint(self, record: InstanceRecord) -> str:
        return self.fingerprint

    def start_instance(
        self, record: InstanceRecord, *, snapshot_dir: Path | None = None
    ) -> LaunchResult:
        self.start_calls.append(record.instance_id)
        self.start_snapshot_dirs.append(snapshot_dir)
        if self.start_error is not None:
            raise self.start_error
        record.runtime_dir.mkdir(parents=True, exist_ok=True)
        (record.runtime_dir / "cvd-start.log").write_text("started\n")
        return LaunchResult(
            launch_command=self.build_start_command(record, snapshot_dir=snapshot_dir),
            adb_port=6520 + record.instance_num - 1,
            adb_serial=None,
            webrtc_port=None,
            backend_runtime_id=(
                "docker-runtime"
                if self.kind == CuttlefishBackendKind.DOCKER
                else None
            ),
        )

    def stop_instance(self, record: InstanceRecord) -> None:
        self.stop_calls.append(record.instance_id)
        if self.stop_error is not None:
            raise self.stop_error
        record.runtime_dir.mkdir(parents=True, exist_ok=True)
        (record.runtime_dir / "cvd-stop.log").write_text("stopped\n")

    def read_logs(self, record: InstanceRecord) -> BackendLogs:
        start_log_path = record.runtime_dir / "cvd-start.log"
        stop_log_path = record.runtime_dir / "cvd-stop.log"
        return BackendLogs(
            start_log=start_log_path.read_text() if start_log_path.exists() else "",
            stop_log=stop_log_path.read_text() if stop_log_path.exists() else "",
        )

    def reconcile(
        self, records: Sequence[InstanceRecord]
    ) -> list[BackendReconcileFailure]:
        del records
        return []


class FakeAppLoader:
    def __init__(self) -> None:
        self.loaded_instance_ids: list[str] = []

    def load_apps(self, record) -> None:
        self.loaded_instance_ids.append(record.instance_id)


class FailingAppLoader:
    def load_apps(self, record) -> None:
        raise RuntimeError("install failed")


class ManagerFixture:
    """Builds a server manager over a fake host backend and temp directories."""

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.db = InstanceDb(self.root / "db.sqlite")
        self.backend = FakeBackend()
        self.app_loader = FakeAppLoader()
        self.settings = type(
            "Settings",
            (),
            {
                "server_host": "127.0.0.1",
                "server_port": 8000,
                "database_path": self.root / "db.sqlite",
                "instance_runtime_root": self.root / "instances",
                "snapshot_root": self.root / "snapshots",
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
                    ),
                    "snap": InstanceTemplate(
                        name="snap",
                        runtime_root=Path("/cf-legacy"),
                        command_mode=CvdCommandMode.LEGACY,
                        cvd_binary=Path("/cf-legacy/bin/cvd"),
                        cpus=2,
                        kernel_path=None,
                        initrd_path=None,
                        selinux=True,
                        apps=(Path("/app-one.apk"),),
                        snapshot_supported=True,
                    ),
                },
            },
        )()
        self.manager = CuttlefishServerManager(
            self.settings,
            self.db,
            {CuttlefishBackendKind.HOST: self.backend},
            self.app_loader,
        )
        self.manager.initialize()

    def tearDown(self) -> None:
        self.db.close()
        self.tempdir.cleanup()


class ServerManagerTests(ManagerFixture, unittest.TestCase):
    def test_unnamed_instances_fall_back_to_instance_id(self):
        created = self.manager.create_instance(
            "alice",
            CreateInstanceRequest(template_name="phone"),
        ).instance

        self.assertEqual(created.instance_name, created.instance_id)
        self.assertEqual(created.adb_port, 6520)
        self.assertTrue(created.load_apps)
        self.assertFalse(created.unmanaged)
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

    def test_manager_dispatches_to_template_backend_and_persists_runtime_id(self):
        docker_backend = FakeBackend(CuttlefishBackendKind.DOCKER)
        self.settings.templates["docker-phone"] = InstanceTemplate(
            name="docker-phone",
            runtime_root=Path("/cf"),
            command_mode=CvdCommandMode.CVD,
            cvd_binary=Path("/cf/bin/cvd"),
            cpus=2,
            kernel_path=None,
            initrd_path=None,
            selinux=True,
            apps=(),
            backend=CuttlefishBackendKind.DOCKER,
            docker_image="cuttlefish:test",
        )
        manager = CuttlefishServerManager(
            self.settings,
            self.db,
            {
                CuttlefishBackendKind.HOST: self.backend,
                CuttlefishBackendKind.DOCKER: docker_backend,
            },
            self.app_loader,
        )

        created = manager.create_instance(
            "alice",
            CreateInstanceRequest(template_name="docker-phone"),
        ).instance
        record = self.db.get(created.instance_id)
        assert record is not None

        self.assertEqual(docker_backend.start_calls, [created.instance_id])
        self.assertEqual(self.backend.start_calls, [])
        self.assertEqual(created.backend, CuttlefishBackendKind.DOCKER)
        self.assertEqual(created.docker_image, "cuttlefish:test")
        self.assertEqual(record.backend_runtime_id, "docker-runtime")

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
            {CuttlefishBackendKind.HOST: self.backend},
            FailingAppLoader(),
        )

        with self.assertRaises(InstanceError) as exc_info:
            manager.create_instance("alice", CreateInstanceRequest(template_name="phone"))

        self.assertIn("failed to load apps", str(exc_info.exception))
        crashed_records = [record for record in self.db.list_instances("alice")]
        self.assertEqual(len(crashed_records), 1)
        self.assertEqual(crashed_records[0].state, InstanceState.CRASHED)
        self.assertIn("install failed", crashed_records[0].failure_reason or "")
        self.assertEqual(self.backend.stop_calls, [crashed_records[0].instance_id])
        self.assertTrue(crashed_records[0].runtime_dir.exists())

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

    def test_restart_preserves_identity_config_and_adb_port_and_resets_lease(self):
        created = self.manager.create_instance(
            "alice",
            CreateInstanceRequest(
                template_name="phone",
                instance_name="demo",
                overrides={
                    "cpus": 6,
                    "selinux": False,
                    "load_apps": True,
                    "unmanaged": True,
                },
            ),
        ).instance
        original_record = self.db.get(created.instance_id)
        assert original_record is not None
        original_config = original_record.config.model_copy(deep=True)
        original_record.expires_at = utc_now() + timedelta(seconds=1)
        self.db.upsert(original_record)

        restarted = self.manager.restart_instance_by_name(
            "alice",
            is_admin=False,
            instance_name="demo",
        )

        restarted_record = self.db.get(created.instance_id)
        assert restarted_record is not None
        self.assertEqual(restarted.state, InstanceState.ACTIVE)
        self.assertEqual(restarted.instance_id, created.instance_id)
        self.assertEqual(restarted.instance_name, created.instance_name)
        self.assertEqual(restarted.instance_num, created.instance_num)
        self.assertEqual(restarted.runtime_dir, created.runtime_dir)
        self.assertEqual(restarted.adb_port, created.adb_port)
        self.assertTrue(restarted.unmanaged)
        self.assertEqual(restarted_record.config, original_config)
        self.assertIsNotNone(restarted.expires_at)
        assert restarted.expires_at is not None
        self.assertGreater(restarted.expires_at, utc_now() + timedelta(seconds=30))
        self.assertEqual(
            self.backend.start_calls,
            [created.instance_id, created.instance_id],
        )
        self.assertEqual(self.backend.stop_calls, [created.instance_id])
        self.assertEqual(
            self.app_loader.loaded_instance_ids,
            [created.instance_id, created.instance_id],
        )

    def test_restart_uses_instance_id_as_effective_name(self):
        created = self.manager.create_instance(
            "alice",
            CreateInstanceRequest(template_name="phone"),
        ).instance

        restarted = self.manager.restart_instance_by_name(
            "alice",
            is_admin=False,
            instance_name=created.instance_id,
        )

        self.assertEqual(restarted.instance_id, created.instance_id)
        self.assertEqual(restarted.state, InstanceState.ACTIVE)

    def test_restart_rejects_non_active_instance(self):
        created = self.manager.create_instance(
            "alice",
            CreateInstanceRequest(template_name="phone", instance_name="demo"),
        ).instance
        self.manager.stop_instance(
            "alice",
            is_admin=False,
            instance_id=created.instance_id,
        )

        with self.assertRaisesRegex(InstanceError, "is not active"):
            self.manager.restart_instance_by_name(
                "alice",
                is_admin=False,
                instance_name="demo",
            )

        self.assertEqual(self.backend.start_calls, [created.instance_id])

    def test_restart_continues_after_stop_failure_and_preserves_warning(self):
        created = self.manager.create_instance(
            "alice",
            CreateInstanceRequest(template_name="phone", instance_name="demo"),
        ).instance
        self.backend.stop_error = RuntimeError("old runtime did not stop cleanly")

        restarted = self.manager.restart_instance_by_name(
            "alice",
            is_admin=False,
            instance_name="demo",
        )
        logs = self.manager.get_instance_logs(
            "alice",
            is_admin=False,
            instance_id=created.instance_id,
        )

        self.assertEqual(restarted.state, InstanceState.ACTIVE)
        self.assertEqual(
            self.backend.start_calls,
            [created.instance_id, created.instance_id],
        )
        self.assertIn("restart stop warning", logs.stop_log)
        self.assertIn("old runtime did not stop cleanly", logs.stop_log)

    def test_restart_attempts_start_after_stop_failure_and_reports_both_logs(self):
        created = self.manager.create_instance(
            "alice",
            CreateInstanceRequest(template_name="phone", instance_name="demo"),
        ).instance
        self.backend.stop_error = RuntimeError("stop failed")
        self.backend.start_error = RuntimeError("port remains in use")

        with self.assertRaisesRegex(InstanceError, "port remains in use"):
            self.manager.restart_instance_by_name(
                "alice",
                is_admin=False,
                instance_name="demo",
            )

        record = self.db.get(created.instance_id)
        assert record is not None
        logs = self.manager.get_instance_logs(
            "alice",
            is_admin=False,
            instance_id=created.instance_id,
        )
        self.assertEqual(record.state, InstanceState.CRASHED)
        self.assertEqual(
            self.backend.start_calls,
            [created.instance_id, created.instance_id],
        )
        self.assertIn("restart stop warning: stop failed", logs.stop_log)
        self.assertIn("port remains in use", record.failure_reason or "")

    def test_restart_runtime_cleanup_failure_prevents_start(self):
        created = self.manager.create_instance(
            "alice",
            CreateInstanceRequest(template_name="phone", instance_name="demo"),
        ).instance

        with patch(
            "cuttle_server.server_manager.shutil.rmtree",
            side_effect=OSError("permission denied"),
        ):
            with self.assertRaisesRegex(InstanceError, "cleanup failed"):
                self.manager.restart_instance_by_name(
                    "alice",
                    is_admin=False,
                    instance_name="demo",
                )

        record = self.db.get(created.instance_id)
        assert record is not None
        self.assertEqual(record.state, InstanceState.CRASHED)
        self.assertEqual(self.backend.start_calls, [created.instance_id])

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


class HostSnapshotBackendTests(unittest.TestCase):
    def _record(self, runtime_root: Path, runtime_dir: Path, *, snapshots: bool):
        config = ResolvedLaunchConfig(
            template_name="phone",
            cpus=4,
            selinux=True,
            runtime_root=runtime_root,
            kernel_path=None,
            initrd_path=None,
            apps=[],
            command_mode=CvdCommandMode.LEGACY,
            cvd_binary=runtime_root / "bin" / "cvd",
            snapshot_compatible=snapshots,
        )
        record = type("Record", (), {})()
        record.instance_num = 3
        record.instance_id = "inst-1"
        record.runtime_dir = runtime_dir
        record.config = config
        return record

    def test_snapshot_instances_launch_with_required_flags(self):
        record = self._record(Path("/cf"), Path("/rt"), snapshots=True)

        command = HostCuttlefishBackend().build_start_command(record)

        self.assertEqual(
            command[-3:],
            [
                "--snapshot_compatible",
                "--gpu_mode=guest_swiftshader",
                "--vhost_user_vsock=false",
            ],
        )

    def test_restore_adds_snapshot_path_to_the_same_flags(self):
        record = self._record(Path("/cf"), Path("/rt"), snapshots=True)

        command = HostCuttlefishBackend().build_start_command(
            record, snapshot_dir=Path("/snapshots/abc")
        )

        self.assertIn("--snapshot_compatible", command)
        self.assertEqual(command[-1], "--snapshot_path=/snapshots/abc")

    def test_plain_instances_get_no_snapshot_flags(self):
        record = self._record(Path("/cf"), Path("/rt"), snapshots=False)

        command = HostCuttlefishBackend().build_start_command(record)

        self.assertFalse([arg for arg in command if "snapshot" in arg])
        self.assertFalse([arg for arg in command if "vhost_user_vsock" in arg])

    def test_restore_dates_snapshot_overlays_after_the_rebuilt_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_dir = Path(tmp)
            instance_dir = snapshot_dir / "instances" / "cvd-3"
            instance_dir.mkdir(parents=True)
            for name in ("overlay.img", "ap_overlay.img", "os_composite.img"):
                (instance_dir / name).write_bytes(b"x")
                os.utime(instance_dir / name, (1_000_000, 1_000_000))

            protected = HostCuttlefishBackend.protect_snapshot_overlays(snapshot_dir)

            self.assertEqual(
                [path.name for path in protected], ["ap_overlay.img", "overlay.img"]
            )
            now = time.time()
            for path in protected:
                self.assertGreater(path.stat().st_mtime, now + 3600)
            self.assertEqual(
                (instance_dir / "os_composite.img").stat().st_mtime, 1_000_000
            )
            self.assertEqual((instance_dir / "overlay.img").read_bytes(), b"x")

    def test_restore_requires_a_snapshot_enabled_instance(self):
        record = self._record(Path("/cf"), Path("/rt"), snapshots=False)

        with self.assertRaisesRegex(RuntimeError, "snapshot support"):
            HostCuttlefishBackend().build_start_command(
                record, snapshot_dir=Path("/snapshots/abc")
            )

    def test_take_snapshot_runs_snapshot_util_in_the_instance_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime_dir = Path(tmp) / "runtime"
            record = self._record(Path("/cf"), runtime_dir, snapshots=True)

            with patch("cuttle_server.backends.host.subprocess.run") as run:
                HostCuttlefishBackend().take_snapshot(record, Path("/snapshots/abc"))

        self.assertEqual(run.call_count, 1)
        self.assertEqual(
            run.call_args.args[0],
            [
                "/cf/bin/snapshot_util_cvd",
                "--subcmd=snapshot_take",
                "--snapshot_path=/snapshots/abc",
                "--auto_suspend",
            ],
        )
        self.assertEqual(run.call_args.kwargs["env"]["HOME"], str(runtime_dir))
        self.assertEqual(run.call_args.kwargs["cwd"], runtime_dir)

    def test_failed_snapshot_tries_to_resume_the_instance_and_reports_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = self._record(Path("/cf"), Path(tmp) / "runtime", snapshots=True)
            calls: list[list[str]] = []

            def fake_run(command, **kwargs):
                calls.append(command)
                if "--subcmd=snapshot_take" in command:
                    raise subprocess.CalledProcessError(1, command)

            with patch("cuttle_server.backends.host.subprocess.run", fake_run):
                with self.assertRaisesRegex(RuntimeError, "snapshot command failed"):
                    HostCuttlefishBackend().take_snapshot(
                        record, Path("/snapshots/abc")
                    )

        self.assertEqual(
            calls[-1], ["/cf/bin/snapshot_util_cvd", "--subcmd=resume"]
        )

    def test_fingerprint_changes_when_crosvm_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime_root = Path(tmp) / "cf"
            native = runtime_root / "bin" / f"{platform.machine()}-linux-musl"
            native.mkdir(parents=True)
            for name in ("run_cvd", "assemble_cvd", "snapshot_util_cvd"):
                (runtime_root / "bin" / name).write_bytes(name.encode())
            (native / "crosvm").write_bytes(b"crosvm-1")
            record = self._record(runtime_root, Path(tmp) / "rt", snapshots=True)
            backend = HostCuttlefishBackend()

            before = backend.host_tools_fingerprint(record)
            self.assertEqual(before, backend.host_tools_fingerprint(record))
            (native / "crosvm").write_bytes(b"crosvm-2")
            after = backend.host_tools_fingerprint(record)

        self.assertNotEqual(before, after)


class SnapshotManagerTests(ManagerFixture, unittest.TestCase):
    def _start(
        self,
        user: str = "alice",
        name: str | None = "demo",
        *,
        snapshots: bool = True,
        template: str = "snap",
    ):
        return self.manager.create_instance(
            user,
            CreateInstanceRequest(
                template_name=template,
                instance_name=name,
                overrides={"snapshots_enabled": snapshots},
            ),
        ).instance

    def _snapshot(
        self,
        instance: str = "demo",
        name: str = "snap1",
        *,
        user: str = "alice",
        is_admin: bool = False,
    ):
        return self.manager.create_snapshot(
            user,
            is_admin,
            instance,
            CreateSnapshotRequest(snapshot_name=name),
        )

    def _restore(
        self,
        instance: str = "demo",
        name: str = "snap1",
        *,
        user: str = "alice",
        is_admin: bool = False,
    ):
        return self.manager.restore_snapshot(
            user,
            is_admin,
            instance,
            RestoreSnapshotRequest(snapshot_name=name),
        )

    # -- launching ---------------------------------------------------

    def test_snapshots_require_a_template_that_supports_them(self):
        with self.assertRaisesRegex(InstanceError, "does not support snapshots"):
            self._start(template="phone")

    def test_snapshot_launch_is_recorded_on_the_instance(self):
        enabled = self._start("alice", "on", snapshots=True)
        disabled = self._start("alice", "off", snapshots=False)

        self.assertTrue(enabled.snapshots_enabled)
        self.assertIn("--snapshots", enabled.launch_command)
        self.assertFalse(disabled.snapshots_enabled)
        self.assertNotIn("--snapshots", disabled.launch_command)

    # -- creating ----------------------------------------------------

    def test_create_snapshot_records_source_and_stores_data_under_snapshot_root(self):
        instance = self._start()

        snapshot = self._snapshot()

        self.assertEqual(snapshot.state, SnapshotState.READY)
        self.assertEqual(snapshot.snapshot_name, "snap1")
        self.assertEqual(snapshot.owner_id, "alice")
        self.assertEqual(snapshot.source_instance_id, instance.instance_id)
        self.assertEqual(snapshot.source_instance_name, "demo")
        self.assertEqual(snapshot.template_name, "snap")
        self.assertEqual(snapshot.instance_num, instance.instance_num)
        self.assertGreater(snapshot.size_bytes or 0, 0)
        record = self.db.get_snapshot(snapshot.snapshot_id)
        assert record is not None
        self.assertTrue(record.snapshot_dir.is_relative_to(self.root / "snapshots"))
        self.assertTrue(record.snapshot_dir.is_dir())
        self.assertEqual(record.runtime_dir, instance.runtime_dir)
        self.assertEqual(record.host_tools_fingerprint, "fingerprint-1")
        self.assertEqual(
            self.backend.snapshot_calls,
            [(instance.instance_id, record.snapshot_dir)],
        )

    def test_create_snapshot_requires_an_active_snapshot_enabled_instance(self):
        self._start("alice", "plain", snapshots=False)
        self._start("alice", "on")

        with self.assertRaisesRegex(InstanceError, "--snapshots"):
            self._snapshot("plain")
        self.manager.stop_instance_by_name("alice", False, "on")
        with self.assertRaisesRegex(InstanceError, "is not active"):
            self._snapshot("on")
        self.assertEqual(self.backend.snapshot_calls, [])

    def test_snapshot_names_are_unique_per_owner(self):
        self._start("alice", "demo")
        self._start("bob", "demo")
        self._snapshot("demo", "snap1", user="alice")

        with self.assertRaisesRegex(InstanceError, "already in use"):
            self._snapshot("demo", "snap1", user="alice")
        bobs = self._snapshot("demo", "snap1", user="bob")

        self.assertEqual(bobs.owner_id, "bob")

    def test_failed_snapshot_is_recorded_and_its_name_can_be_reused(self):
        self._start()
        self.backend.snapshot_error = RuntimeError("crosvm exploded")

        with self.assertRaisesRegex(InstanceError, "crosvm exploded"):
            self._snapshot()

        failed = self.manager.list_snapshots("alice", False).snapshots
        self.assertEqual([s.state for s in failed], [SnapshotState.FAILED])
        self.assertIn("crosvm exploded", failed[0].failure_reason or "")
        self.assertEqual(list((self.root / "snapshots").glob("*")), [])

        self.backend.snapshot_error = None
        retry = self._snapshot()

        self.assertEqual(retry.state, SnapshotState.READY)
        remaining = self.manager.list_snapshots("alice", False).snapshots
        self.assertEqual([s.snapshot_id for s in remaining], [retry.snapshot_id])

    def test_admin_snapshot_of_another_users_instance_belongs_to_that_user(self):
        self._start("alice", "demo")

        snapshot = self._snapshot("demo", "snap1", user="admin", is_admin=True)

        self.assertEqual(snapshot.owner_id, "alice")
        visible = self.manager.list_snapshots("alice", False).snapshots
        self.assertEqual([s.snapshot_id for s in visible], [snapshot.snapshot_id])

    # -- listing / visibility / deleting -----------------------------

    def test_list_scopes_to_the_user_and_admin_sees_everything(self):
        self._start("alice", "a")
        self._start("bob", "b")
        mine = self._snapshot("a", "mine", user="alice")
        theirs = self._snapshot("b", "theirs", user="bob")

        alice = self.manager.list_snapshots("alice", False).snapshots
        admin = self.manager.list_snapshots("admin", True).snapshots

        self.assertEqual([s.snapshot_id for s in alice], [mine.snapshot_id])
        self.assertEqual(
            {s.snapshot_id for s in admin}, {mine.snapshot_id, theirs.snapshot_id}
        )

    def test_list_filters_by_source_instance_and_template(self):
        a = self._start("alice", "a")
        self._start("alice", "b")
        first = self._snapshot("a", "one")
        second = self._snapshot("b", "two")

        by_name = self.manager.list_snapshots("alice", False, instance="a").snapshots
        by_id = self.manager.list_snapshots(
            "alice", False, instance=a.instance_id
        ).snapshots
        by_template = self.manager.list_snapshots(
            "alice", False, template_name="snap"
        ).snapshots
        other_template = self.manager.list_snapshots(
            "alice", False, template_name="phone"
        ).snapshots

        self.assertEqual([s.snapshot_id for s in by_name], [first.snapshot_id])
        self.assertEqual([s.snapshot_id for s in by_id], [first.snapshot_id])
        self.assertEqual(
            {s.snapshot_id for s in by_template},
            {first.snapshot_id, second.snapshot_id},
        )
        self.assertEqual(other_template, [])

    def test_get_enforces_visibility_by_name_and_by_id(self):
        self._start("alice", "demo")
        snapshot = self._snapshot()

        with self.assertRaises(NotFoundError):
            self.manager.get_snapshot_by_name("bob", False, "snap1")
        with self.assertRaises(AuthorizationError):
            self.manager.get_snapshot_by_name("bob", False, snapshot.snapshot_id)
        shown = self.manager.get_snapshot_by_name("admin", True, "snap1")

        self.assertEqual(shown.snapshot_id, snapshot.snapshot_id)

    def test_admin_lookup_of_a_name_shared_by_users_is_ambiguous(self):
        self._start("alice", "demo")
        self._start("bob", "demo")
        self._snapshot("demo", "snap1", user="alice")
        self._snapshot("demo", "snap1", user="bob")

        with self.assertRaisesRegex(InstanceError, "ambiguous"):
            self.manager.get_snapshot_by_name("admin", True, "snap1")

    def test_delete_removes_data_and_record(self):
        self._start()
        snapshot = self._snapshot()
        record = self.db.get_snapshot(snapshot.snapshot_id)
        assert record is not None

        self.manager.delete_snapshot_by_name("alice", False, "snap1")

        self.assertFalse(record.snapshot_dir.exists())
        self.assertIsNone(self.db.get_snapshot(snapshot.snapshot_id))
        with self.assertRaises(NotFoundError):
            self.manager.get_snapshot_by_name("alice", False, "snap1")

    def test_delete_is_refused_while_a_restore_is_reading_the_snapshot(self):
        self._start()
        snapshot = self._snapshot()
        self.manager._restoring_snapshot_ids.add(snapshot.snapshot_id)

        with self.assertRaisesRegex(InstanceError, "being restored"):
            self.manager.delete_snapshot_by_name("alice", False, "snap1")

        self.assertIsNotNone(self.db.get_snapshot(snapshot.snapshot_id))

    def test_snapshot_data_outside_the_snapshot_root_is_never_deleted(self):
        self._start()
        snapshot = self._snapshot()
        record = self.db.get_snapshot(snapshot.snapshot_id)
        assert record is not None
        precious = self.root / "precious"
        precious.mkdir()
        record.snapshot_dir = precious
        self.db.upsert_snapshot(record)

        with self.assertRaisesRegex(InstanceError, "outside the snapshot root"):
            self.manager.delete_snapshot_by_name("alice", False, "snap1")

        self.assertTrue(precious.is_dir())

    def test_snapshots_interrupted_by_a_server_restart_are_marked_failed(self):
        self._start()
        snapshot = self._snapshot()
        record = self.db.get_snapshot(snapshot.snapshot_id)
        assert record is not None
        record.state = SnapshotState.CREATING
        self.db.upsert_snapshot(record)

        self.manager.initialize()

        reloaded = self.db.get_snapshot(snapshot.snapshot_id)
        assert reloaded is not None
        self.assertEqual(reloaded.state, SnapshotState.FAILED)
        self.assertIn("server restart", reloaded.failure_reason or "")
        self.assertFalse(record.snapshot_dir.exists())

    # -- restoring ---------------------------------------------------

    def test_restore_stops_a_running_instance_and_restarts_it_from_the_snapshot(self):
        created = self._start()
        snapshot = self._snapshot()
        record = self.db.get_snapshot(snapshot.snapshot_id)
        assert record is not None
        (created.runtime_dir / "scratch").write_text("state after snapshot")

        restored = self._restore()

        self.assertEqual(restored.state, InstanceState.ACTIVE)
        self.assertEqual(restored.instance_id, created.instance_id)
        self.assertEqual(restored.instance_num, created.instance_num)
        self.assertEqual(restored.runtime_dir, created.runtime_dir)
        self.assertEqual(restored.adb_port, created.adb_port)
        self.assertTrue(restored.snapshots_enabled)
        self.assertIn(f"--snapshot_path={record.snapshot_dir}", restored.launch_command)
        self.assertEqual(self.backend.stop_calls, [created.instance_id])
        self.assertEqual(self.backend.start_snapshot_dirs, [None, record.snapshot_dir])
        self.assertFalse((created.runtime_dir / "scratch").exists())
        # The restored guest already has its apps; they are not installed again.
        self.assertEqual(self.app_loader.loaded_instance_ids, [created.instance_id])
        # Restoring leaves the snapshot intact and releases it.
        self.assertTrue(record.snapshot_dir.is_dir())
        self.assertEqual(self.manager._restoring_snapshot_ids, set())

    def test_restore_resets_the_lease(self):
        self._start()
        self._snapshot()

        restored = self._restore()

        assert restored.expires_at is not None
        self.assertGreater(restored.expires_at, utc_now() + timedelta(seconds=30))

    def test_restore_revives_a_stopped_instance_without_stopping_it_again(self):
        created = self._start()
        self._snapshot()
        self.manager.stop_instance_by_name("alice", False, "demo")
        self.assertFalse(created.runtime_dir.exists())

        restored = self._restore()

        self.assertEqual(restored.state, InstanceState.ACTIVE)
        self.assertEqual(restored.instance_name, "demo")
        self.assertEqual(self.backend.stop_calls, [created.instance_id])
        self.assertEqual(len(self.backend.start_calls), 2)

    def test_restore_revives_an_expired_instance(self):
        created = self._start()
        self._snapshot()
        record = self.db.get(created.instance_id)
        assert record is not None
        record.expires_at = utc_now() - timedelta(seconds=1)
        self.db.upsert(record)
        self.manager.reconcile_expired_instances()
        expired = self.db.get(created.instance_id)
        assert expired is not None
        self.assertEqual(expired.state, InstanceState.EXPIRED)

        restored = self._restore()

        self.assertEqual(restored.state, InstanceState.ACTIVE)

    def test_restore_into_a_stopped_instance_fails_if_its_slot_was_taken(self):
        created = self._start()
        self._snapshot()
        self.manager.stop_instance_by_name("alice", False, "demo")
        newcomer = self._start("bob", "other")
        self.assertEqual(newcomer.instance_num, created.instance_num)

        with self.assertRaisesRegex(InstanceError, "instance number"):
            self._restore()

        stopped = self.db.get(created.instance_id)
        assert stopped is not None
        self.assertEqual(stopped.state, InstanceState.STOPPED)

    def test_restore_into_a_different_instance_is_rejected(self):
        self._start("alice", "first")
        self._start("alice", "second")
        self._snapshot("first", "snap1")

        with self.assertRaisesRegex(InstanceError, "instance number and runtime"):
            self._restore("second", "snap1")

        self.assertEqual(self.backend.stop_calls, [])

    def test_restore_is_rejected_when_the_host_tools_changed(self):
        self._start()
        self._snapshot()
        self.backend.fingerprint = "fingerprint-2"

        with self.assertRaisesRegex(InstanceError, "host tools changed"):
            self._restore()

        self.assertEqual(self.backend.stop_calls, [])

    def test_restore_rejects_snapshots_that_are_not_ready(self):
        self._start()
        self.backend.snapshot_error = RuntimeError("nope")
        with self.assertRaises(InstanceError):
            self._snapshot()
        self.backend.snapshot_error = None

        with self.assertRaisesRegex(InstanceError, "not ready"):
            self._restore()

    def test_restore_rejects_instances_that_are_starting(self):
        created = self._start()
        self._snapshot()
        record = self.db.get(created.instance_id)
        assert record is not None
        record.state = InstanceState.STARTING
        self.db.upsert(record)

        with self.assertRaisesRegex(InstanceError, "starting"):
            self._restore()

    def test_restore_enforces_visibility(self):
        self._start("alice", "demo")
        self._snapshot()

        with self.assertRaises(NotFoundError):
            self._restore(user="bob")
        restored = self._restore(user="admin", is_admin=True)

        self.assertEqual(restored.state, InstanceState.ACTIVE)

    def test_failed_restore_crashes_the_instance_but_keeps_the_snapshot(self):
        created = self._start()
        snapshot = self._snapshot()
        self.backend.start_error = RuntimeError("restore blew up")

        with self.assertRaisesRegex(InstanceError, "restore blew up"):
            self._restore()

        crashed = self.db.get(created.instance_id)
        assert crashed is not None
        self.assertEqual(crashed.state, InstanceState.CRASHED)
        self.assertIn("restore blew up", crashed.failure_reason or "")
        self.assertEqual(self.manager._restoring_snapshot_ids, set())
        kept = self.db.get_snapshot(snapshot.snapshot_id)
        assert kept is not None
        self.assertEqual(kept.state, SnapshotState.READY)
        self.assertTrue(kept.snapshot_dir.is_dir())

        # The instance can be restored again once the problem is gone.
        self.backend.start_error = None
        self.assertEqual(self._restore().state, InstanceState.ACTIVE)


class SnapshotApiTests(unittest.TestCase):
    """Drives the snapshot endpoints through a real FastAPI app."""

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        self.backend = FakeBackend()
        self.settings = CuttlefishSettings(
            server_host="127.0.0.1",
            server_port=8000,
            auth_token="tok",
            admin_user_id="admin",
            database_path=root / "db.sqlite",
            instance_runtime_root=root / "instances",
            instance_timeout_sec=None,
            cvd_start_timeout_sec=120,
            reconcile_interval_sec=3600,
            base_instance_num=0,
            max_instances=5,
            snapshot_root=root / "snapshots",
            templates={
                "snap": InstanceTemplate(
                    name="snap",
                    runtime_root=Path("/cf-legacy"),
                    command_mode=CvdCommandMode.LEGACY,
                    cvd_binary=Path("/cf-legacy/bin/cvd"),
                    cpus=2,
                    kernel_path=None,
                    initrd_path=None,
                    selinux=True,
                    apps=(),
                    snapshot_supported=True,
                ),
                "plain": InstanceTemplate(
                    name="plain",
                    runtime_root=Path("/cf"),
                    command_mode=CvdCommandMode.CVD,
                    cvd_binary=Path("/cf/bin/cvd"),
                    cpus=2,
                    kernel_path=None,
                    initrd_path=None,
                    selinux=True,
                    apps=(),
                ),
            },
        )
        patches = [
            patch("cuttle_server.api.HostCuttlefishBackend", return_value=self.backend),
            patch(
                "cuttle_server.api.DockerCuttlefishBackend",
                return_value=FakeBackend(CuttlefishBackendKind.DOCKER),
            ),
        ]
        for started in patches:
            started.start()
            self.addCleanup(started.stop)
        self.client = TestClient(create_app(self.settings))
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        self.addCleanup(self.tempdir.cleanup)

    @staticmethod
    def headers(user: str = "alice") -> dict[str, str]:
        return {"Authorization": "Bearer tok", "X-User-Id": user}

    def _start(self, name: str = "demo", user: str = "alice", template: str = "snap"):
        return self.client.post(
            "/v1/instances",
            headers=self.headers(user),
            json={
                "template_name": template,
                "instance_name": name,
                "overrides": {"snapshots_enabled": True},
            },
        )

    def test_snapshot_lifecycle_over_http(self) -> None:
        started = self._start()
        self.assertEqual(started.status_code, 201, started.text)
        self.assertTrue(started.json()["instance"]["snapshots_enabled"])

        created = self.client.post(
            "/v1/instances/by-name/demo/snapshots",
            headers=self.headers(),
            json={"snapshot_name": "snap1"},
        )
        self.assertEqual(created.status_code, 201, created.text)
        body = created.json()
        self.assertEqual(body["state"], "ready")
        self.assertEqual(body["source_instance_name"], "demo")

        listed = self.client.get("/v1/snapshots", headers=self.headers())
        self.assertEqual([s["snapshot_name"] for s in listed.json()["snapshots"]], ["snap1"])
        shown = self.client.get("/v1/snapshots/by-name/snap1", headers=self.headers())
        self.assertEqual(shown.json()["snapshot_id"], body["snapshot_id"])

        restored = self.client.post(
            "/v1/instances/by-name/demo/restore",
            headers=self.headers(),
            json={"snapshot_name": "snap1"},
        )
        self.assertEqual(restored.status_code, 200, restored.text)
        self.assertEqual(restored.json()["state"], "active")
        self.assertIsNotNone(self.backend.start_snapshot_dirs[-1])

        deleted = self.client.delete(
            "/v1/snapshots/by-name/snap1", headers=self.headers()
        )
        self.assertEqual(deleted.status_code, 200, deleted.text)
        gone = self.client.get("/v1/snapshots/by-name/snap1", headers=self.headers())
        self.assertEqual(gone.status_code, 404)

    def test_list_filters_are_query_parameters(self) -> None:
        self._start("a")
        self._start("b")
        for instance, name in (("a", "one"), ("b", "two")):
            self.client.post(
                f"/v1/instances/by-name/{instance}/snapshots",
                headers=self.headers(),
                json={"snapshot_name": name},
            )

        by_instance = self.client.get(
            "/v1/snapshots", params={"instance": "a"}, headers=self.headers()
        )
        by_template = self.client.get(
            "/v1/snapshots", params={"template": "plain"}, headers=self.headers()
        )

        self.assertEqual(
            [s["snapshot_name"] for s in by_instance.json()["snapshots"]], ["one"]
        )
        self.assertEqual(by_template.json()["snapshots"], [])

    def test_errors_map_to_http_status_codes(self) -> None:
        self._start()
        create = "/v1/instances/by-name/demo/snapshots"

        no_token = self.client.get("/v1/snapshots")
        missing_instance = self.client.post(
            "/v1/instances/by-name/nope/snapshots",
            headers=self.headers(),
            json={"snapshot_name": "snap1"},
        )
        other_users_instance = self.client.post(
            create, headers=self.headers("bob"), json={"snapshot_name": "snap1"}
        )
        first = self.client.post(
            create, headers=self.headers(), json={"snapshot_name": "snap1"}
        )
        duplicate = self.client.post(
            create, headers=self.headers(), json={"snapshot_name": "snap1"}
        )
        empty_name = self.client.post(
            create, headers=self.headers(), json={"snapshot_name": ""}
        )
        missing_snapshot = self.client.post(
            "/v1/instances/by-name/demo/restore",
            headers=self.headers(),
            json={"snapshot_name": "nope"},
        )
        unsupported = self._start("p", template="plain")

        self.assertEqual(no_token.status_code, 401)
        self.assertEqual(missing_instance.status_code, 404)
        self.assertEqual(other_users_instance.status_code, 404)
        self.assertEqual(first.status_code, 201)
        self.assertEqual(duplicate.status_code, 400)
        self.assertIn("already in use", duplicate.json()["detail"])
        self.assertEqual(empty_name.status_code, 422)
        self.assertEqual(missing_snapshot.status_code, 404)
        self.assertEqual(unsupported.status_code, 400)
        self.assertIn("does not support snapshots", unsupported.json()["detail"])

    def test_snapshots_are_private_to_their_owner_but_visible_to_admin(self) -> None:
        self._start()
        self.client.post(
            "/v1/instances/by-name/demo/snapshots",
            headers=self.headers(),
            json={"snapshot_name": "snap1"},
        )

        bob = self.client.get("/v1/snapshots", headers=self.headers("bob"))
        bob_show = self.client.get(
            "/v1/snapshots/by-name/snap1", headers=self.headers("bob")
        )
        admin = self.client.get("/v1/snapshots", headers=self.headers("admin"))

        self.assertEqual(bob.json()["snapshots"], [])
        self.assertEqual(bob_show.status_code, 404)
        self.assertEqual([s["owner_id"] for s in admin.json()["snapshots"]], ["alice"])
