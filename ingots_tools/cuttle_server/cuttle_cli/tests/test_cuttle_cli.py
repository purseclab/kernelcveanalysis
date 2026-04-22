import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cuttle_types import (
    CreateInstanceResponse,
    InstanceListResponse,
    InstanceState,
    InstanceView,
    TemplateListResponse,
    TemplateSummary,
    TemplateView,
)
from typer.testing import CliRunner

from cuttle_cli.config import CliSettings, load_cli_settings
from cuttle_cli.daemon import (
    DaemonMetadata,
    get_daemon_status,
    render_daemon_identity,
    stop_managed_daemon,
    sync_managed_daemon_once_with_client,
)
from cuttle_cli.main import app


class CliConfigTests(unittest.TestCase):
    def test_load_cli_settings_reads_default_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.toml"
            config_path.write_text(
                'server_host = "example.com"\n'
                "server_port = 9999\n"
                'auth_token = "secret"\n'
                'user_id = "alice"\n'
            )
            with patch("cuttle_cli.config.default_config_path", return_value=config_path):
                settings = load_cli_settings()

        self.assertEqual(settings.server_host, "example.com")
        self.assertEqual(settings.server_port, 9999)
        self.assertEqual(settings.auth_token, "secret")
        self.assertEqual(settings.user_id, "alice")

    def test_load_cli_settings_applies_overrides(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.toml"
            config_path.write_text(
                'server_host = "example.com"\n'
                "server_port = 9999\n"
                'auth_token = "secret"\n'
                'user_id = "alice"\n'
            )
            with patch("cuttle_cli.config.default_config_path", return_value=config_path):
                settings = load_cli_settings(
                    server_host="localhost",
                    server_port=8001,
                    auth_token="override-token",
                    user_id="bob",
                )

        self.assertEqual(settings.server_host, "localhost")
        self.assertEqual(settings.server_port, 8001)
        self.assertEqual(settings.auth_token, "override-token")
        self.assertEqual(settings.user_id, "bob")


class CliCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_help_does_not_require_config(self):
        result = self.runner.invoke(app, ["--help"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("daemon", result.output)

    def _mock_instance(
        self,
        *,
        instance_name: str,
        owner_id: str = "alice",
        state: InstanceState = InstanceState.ACTIVE,
        instance_id: str = "inst-1",
    ) -> InstanceView:
        return InstanceView(
            instance_id=instance_id,
            owner_id=owner_id,
            instance_name=instance_name,
            state=state,
            instance_num=1,
            template_name="phone",
            cpus=4,
            selinux=False,
            kernel_path=Path("/kernel"),
            initrd_path=Path("/initrd"),
            apps=[],
            load_apps=True,
            runtime_dir=Path("/runtime"),
            launch_command=["launch"],
            adb_port=6520,
            adb_serial=None,
            webrtc_port=None,
            expires_at="2026-01-01T00:00:00Z",
            failure_reason=None,
        )

    def test_start_command_uses_optional_name(self):
        mock_client = Mock()
        mock_client.adb_target.return_value = "127.0.0.1:6520"
        mock_client.start_instance.return_value = CreateInstanceResponse(
            instance=self._mock_instance(instance_name="demo")
        )
        with patch("cuttle_cli.main.load_cli_settings"), patch(
            "cuttle_cli.main.CuttleApiClient.from_settings",
            return_value=mock_client,
        ), patch("cuttle_cli.main.ensure_managed_daemon_running"):
            result = self.runner.invoke(
                app,
                ["start", "phone", "--name", "demo", "--cpus", "6"],
            )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("adb=127.0.0.1:6520", result.output)
        request_body = mock_client.start_instance.call_args.args[0]
        self.assertEqual(request_body.template_name, "phone")
        self.assertEqual(request_body.instance_name, "demo")
        self.assertEqual(request_body.overrides.cpus, 6)

    def test_start_command_can_disable_app_loading(self):
        mock_client = Mock()
        mock_client.adb_target.return_value = "127.0.0.1:6520"
        mock_client.start_instance.return_value = CreateInstanceResponse(
            instance=self._mock_instance(instance_name="demo")
        )
        with patch("cuttle_cli.main.load_cli_settings"), patch(
            "cuttle_cli.main.CuttleApiClient.from_settings",
            return_value=mock_client,
        ), patch("cuttle_cli.main.ensure_managed_daemon_running"):
            result = self.runner.invoke(
                app,
                ["start", "phone", "--no-load-apps"],
            )

        self.assertEqual(result.exit_code, 0, result.output)
        request_body = mock_client.start_instance.call_args.args[0]
        self.assertFalse(request_body.overrides.load_apps)

    def test_list_command_prints_instances(self):
        mock_client = Mock()
        mock_client.adb_target.return_value = "127.0.0.1:6520"
        mock_client.list_instances.return_value = InstanceListResponse(
            instances=[self._mock_instance(instance_name="inst-1")]
        )
        with patch("cuttle_cli.main.load_cli_settings"), patch(
            "cuttle_cli.main.CuttleApiClient.from_settings",
            return_value=mock_client,
        ), patch("cuttle_cli.main.ensure_managed_daemon_running"):
            result = self.runner.invoke(app, ["list"])

        self.assertEqual(result.exit_code, 0, result.output)
        lines = result.output.strip().splitlines()
        self.assertEqual(
            lines[0],
            "instance_name  instance_id  state   template  owner  adb_target",
        )
        self.assertEqual(
            lines[1],
            "inst-1         inst-1       active  phone     alice  127.0.0.1:6520",
        )

    def test_list_command_hides_terminal_instances_by_default(self):
        mock_client = Mock()
        mock_client.adb_target.return_value = "127.0.0.1:6520"
        stopped = self._mock_instance(instance_name="stopped")
        stopped.state = InstanceState.STOPPED
        mock_client.list_instances.return_value = InstanceListResponse(
            instances=[stopped]
        )
        with patch("cuttle_cli.main.load_cli_settings"), patch(
            "cuttle_cli.main.CuttleApiClient.from_settings",
            return_value=mock_client,
        ), patch("cuttle_cli.main.ensure_managed_daemon_running"):
            result = self.runner.invoke(app, ["list"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(result.output.strip(), "No instances.")

    def test_list_command_all_shows_terminal_instances(self):
        mock_client = Mock()
        mock_client.adb_target.return_value = "-"
        stopped = self._mock_instance(instance_name="stopped")
        stopped.state = InstanceState.STOPPED
        stopped.adb_port = None
        mock_client.list_instances.return_value = InstanceListResponse(
            instances=[stopped]
        )
        with patch("cuttle_cli.main.load_cli_settings"), patch(
            "cuttle_cli.main.CuttleApiClient.from_settings",
            return_value=mock_client,
        ), patch("cuttle_cli.main.ensure_managed_daemon_running"):
            result = self.runner.invoke(app, ["list", "--all"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("stopped", result.output)

    def test_stop_command_uses_name_endpoint(self):
        mock_client = Mock()
        mock_client.adb_target.return_value = "127.0.0.1:6520"
        mock_client.stop_instance_by_name.return_value = self._mock_instance(
            instance_name="inst-1"
        )
        with patch("cuttle_cli.main.load_cli_settings"), patch(
            "cuttle_cli.main.CuttleApiClient.from_settings",
            return_value=mock_client,
        ), patch("cuttle_cli.main.ensure_managed_daemon_running"):
            result = self.runner.invoke(app, ["stop", "inst-1"])

        self.assertEqual(result.exit_code, 0, result.output)
        mock_client.stop_instance_by_name.assert_called_once_with("inst-1")

    def test_stop_all_stops_all_visible_running_instances(self):
        mock_client = Mock()
        running = self._mock_instance(instance_name="demo", instance_id="inst-1")
        stopped = self._mock_instance(
            instance_name="done",
            instance_id="inst-2",
            state=InstanceState.STOPPED,
        )
        other = self._mock_instance(
            instance_name="other",
            instance_id="inst-3",
            owner_id="bob",
        )
        mock_client.list_instances.return_value = InstanceListResponse(
            instances=[running, stopped, other]
        )
        mock_client.stop_instance.side_effect = [running, other]
        with patch("cuttle_cli.main.load_cli_settings"), patch(
            "cuttle_cli.main.CuttleApiClient.from_settings",
            return_value=mock_client,
        ), patch("cuttle_cli.main.ensure_managed_daemon_running"):
            result = self.runner.invoke(app, ["stop", "--stop-all"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(
            [call.args[0] for call in mock_client.stop_instance.call_args_list],
            ["inst-1", "inst-3"],
        )
        self.assertIn("stopped demo (inst-1)", result.output)
        self.assertIn("stopped other (inst-3)", result.output)

    def test_stop_all_user_stops_only_matching_owner_instances(self):
        mock_client = Mock()
        alice = self._mock_instance(instance_name="alice-1", instance_id="inst-1")
        bob = self._mock_instance(
            instance_name="bob-1",
            instance_id="inst-2",
            owner_id="bob",
        )
        mock_client.list_instances.return_value = InstanceListResponse(
            instances=[alice, bob]
        )
        mock_client.stop_instance.return_value = bob
        with patch("cuttle_cli.main.load_cli_settings"), patch(
            "cuttle_cli.main.CuttleApiClient.from_settings",
            return_value=mock_client,
        ), patch("cuttle_cli.main.ensure_managed_daemon_running"):
            result = self.runner.invoke(app, ["stop", "--stop-all-user", "bob"])

        self.assertEqual(result.exit_code, 0, result.output)
        mock_client.stop_instance.assert_called_once_with("inst-2")
        self.assertIn("owner=bob", result.output)

    def test_stop_all_user_reports_no_matches(self):
        mock_client = Mock()
        mock_client.list_instances.return_value = InstanceListResponse(
            instances=[self._mock_instance(instance_name="alice-1", instance_id="inst-1")]
        )
        with patch("cuttle_cli.main.load_cli_settings"), patch(
            "cuttle_cli.main.CuttleApiClient.from_settings",
            return_value=mock_client,
        ), patch("cuttle_cli.main.ensure_managed_daemon_running"):
            result = self.runner.invoke(app, ["stop", "--stop-all-user", "bob"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(result.output.strip(), "No matching running instances.")
        mock_client.stop_instance.assert_not_called()

    def test_stop_command_rejects_multiple_modes(self):
        mock_client = Mock()
        with patch("cuttle_cli.main.load_cli_settings"), patch(
            "cuttle_cli.main.CuttleApiClient.from_settings",
            return_value=mock_client,
        ), patch("cuttle_cli.main.ensure_managed_daemon_running"):
            result = self.runner.invoke(app, ["stop", "inst-1", "--stop-all"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("specify exactly one", result.output)

    def test_templates_commands_work(self):
        mock_client = Mock()
        mock_client.adb_target.return_value = "127.0.0.1:6520"
        mock_client.list_templates.return_value = TemplateListResponse(
            templates=[TemplateSummary(template_name="phone", cpus=4, selinux=False)]
        )
        mock_client.get_template.return_value = TemplateView(
            template_name="phone",
            runtime_root=Path("/cf"),
            cpus=4,
            kernel_path=Path("/kernel"),
            initrd_path=Path("/initrd"),
            selinux=False,
            apps=[Path("/app.apk")],
        )
        with patch("cuttle_cli.main.load_cli_settings"), patch(
            "cuttle_cli.main.CuttleApiClient.from_settings",
            return_value=mock_client,
        ):
            list_result = self.runner.invoke(app, ["templates", "list"])
            show_result = self.runner.invoke(app, ["templates", "show", "phone"])

        self.assertEqual(list_result.exit_code, 0, list_result.output)
        self.assertEqual(show_result.exit_code, 0, show_result.output)
        self.assertIn("phone", list_result.output)
        self.assertIn("runtime_root: /cf", show_result.output)

    def test_auto_start_calls_daemon_helper(self):
        mock_client = Mock()
        mock_client.adb_target.return_value = "127.0.0.1:6520"
        mock_client.list_instances.return_value = InstanceListResponse(instances=[])
        with patch("cuttle_cli.main.load_cli_settings"), patch(
            "cuttle_cli.main.CuttleApiClient.from_settings",
            return_value=mock_client,
        ), patch("cuttle_cli.main.ensure_managed_daemon_running") as ensure_daemon:
            result = self.runner.invoke(app, ["list"])

        self.assertEqual(result.exit_code, 0, result.output)
        ensure_daemon.assert_called_once()


class DaemonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.settings = CliSettings(
            server_host="example.com",
            server_port=8000,
            auth_token="secret-token",
            user_id="alice",
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _mock_instance(
        self,
        *,
        instance_id: str,
        instance_name: str,
        state: InstanceState = InstanceState.ACTIVE,
        adb_port: int | None = 6520,
    ) -> InstanceView:
        return InstanceView(
            instance_id=instance_id,
            owner_id="alice",
            instance_name=instance_name,
            state=state,
            instance_num=1,
            template_name="phone",
            cpus=4,
            selinux=False,
            kernel_path=Path("/kernel"),
            initrd_path=Path("/initrd"),
            apps=[],
            load_apps=True,
            runtime_dir=Path("/runtime"),
            launch_command=["launch"],
            adb_port=adb_port,
            adb_serial=None,
            webrtc_port=None,
            expires_at="2026-01-01T00:00:00Z",
            failure_reason=None,
        )

    def test_sync_reconciles_adb_endpoints(self):
        mock_client = Mock()
        mock_client.server_host = "example.com"
        mock_client.adb_target.side_effect = lambda instance: (
            None if instance.adb_port is None else f"example.com:{instance.adb_port}"
        )
        mock_client.list_instances.return_value = InstanceListResponse(
            instances=[self._mock_instance(instance_id="inst-1", instance_name="demo")]
        )

        with patch("cuttle_cli.daemon.default_state_dir", return_value=self.root), patch(
            "cuttle_cli.daemon.subprocess.run"
        ) as run:
            run.return_value.returncode = 0
            endpoints = sync_managed_daemon_once_with_client(mock_client)

            mock_client.list_instances.return_value = InstanceListResponse(instances=[])
            endpoints = sync_managed_daemon_once_with_client(mock_client)

        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [["adb", "connect", "example.com:6520"], ["adb", "disconnect", "example.com:6520"]],
        )
        self.assertEqual(endpoints, [])

    def test_status_reads_metadata_and_stop_cleans_files(self):
        metadata = DaemonMetadata(
            pid=4242,
            server_host="example.com",
            server_port=8000,
            user_id="alice",
            auth_token_sha256="0" * 64,
        )
        state_dir = self.root
        (state_dir / "daemon.json").write_text(metadata.model_dump_json(), encoding="utf-8")
        (state_dir / "daemon.pid").write_text("4242\n", encoding="utf-8")
        (state_dir / "owned_endpoints.json").write_text(
            '{"endpoints":["example.com:6520"]}',
            encoding="utf-8",
        )

        with patch("cuttle_cli.daemon.default_state_dir", return_value=state_dir), patch(
            "cuttle_cli.daemon.os.kill",
            side_effect=[None, None, None, ProcessLookupError()],
        ), patch("cuttle_cli.daemon.subprocess.run") as run:
            run.return_value.returncode = 0
            status = get_daemon_status()
            stopped = stop_managed_daemon()

        self.assertTrue(status.running)
        self.assertEqual(render_daemon_identity(status.metadata), "alice@example.com:8000")
        self.assertTrue(stopped)
        self.assertEqual(run.call_args.args[0], ["adb", "disconnect", "example.com:6520"])
        self.assertFalse((state_dir / "daemon.json").exists())
        self.assertFalse((state_dir / "daemon.pid").exists())
