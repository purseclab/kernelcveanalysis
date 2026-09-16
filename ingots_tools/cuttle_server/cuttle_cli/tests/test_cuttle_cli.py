from __future__ import annotations

import tempfile
import unittest
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, call, patch

from click.testing import Result
from cuttle_types import (
    CreateInstanceRequest,
    CreateInstanceResponse,
    CvdCommandMode,
    InstanceListResponse,
    InstanceLogsView,
    InstanceState,
    InstanceView,
    TemplateListResponse,
    TemplateSummary,
    TemplateView,
)
from typer.testing import CliRunner

from cuttle_cli import CuttleClient as ExportedCuttleClient
from cuttle_cli.client import (
    CliError,
    CuttleApiClient,
    CuttleClient,
    StartResult,
    StopFailure,
    StopManyResult,
)
from cuttle_cli.config import (
    CliSettings,
    default_config_path,
    default_state_dir,
    load_cli_settings,
)
from cuttle_cli.daemon import (
    DaemonMetadata,
    DaemonStatus,
    get_daemon_status,
    refresh_adb_connection,
    render_daemon_identity,
    stop_managed_daemon,
    sync_managed_daemon_once_with_client,
)
from cuttle_cli.main import app


def make_settings() -> CliSettings:
    return CliSettings(
        server_host="example.com",
        server_port=8000,
        auth_token="secret-token",
        user_id="alice",
    )


def make_instance(
    *,
    instance_name: str = "demo",
    owner_id: str = "alice",
    state: InstanceState = InstanceState.ACTIVE,
    instance_id: str = "inst-1",
    failure_reason: str | None = None,
    adb_port: int | None = 6520,
    unmanaged: bool = False,
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
        unmanaged=unmanaged,
        runtime_dir=Path("/runtime"),
        launch_command=["launch"],
        adb_port=adb_port,
        adb_serial=None,
        webrtc_port=None,
        expires_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        failure_reason=failure_reason,
    )


def make_logs(
    *,
    instance_id: str = "inst-1",
    instance_name: str = "demo",
    state: InstanceState = InstanceState.ACTIVE,
    start_log: str = "",
    stop_log: str = "",
    failure_reason: str | None = None,
    kernel_log: str = "",
    launcher_log: str = "",
    logcat: str = "",
) -> InstanceLogsView:
    return InstanceLogsView(
        instance_id=instance_id,
        instance_name=instance_name,
        state=state,
        launch_command=["launch"],
        failure_reason=failure_reason,
        start_log=start_log,
        stop_log=stop_log,
        kernel_log=kernel_log,
        launcher_log=launcher_log,
        logcat=logcat,
    )


def make_template() -> TemplateView:
    return TemplateView(
        template_name="phone",
        runtime_root=Path("/cf"),
        cpus=4,
        kernel_path=Path("/kernel"),
        initrd_path=Path("/initrd"),
        selinux=False,
        apps=[Path("/app.apk")],
        command_mode=CvdCommandMode.LEGACY,
    )


class CuttleApiClientTests(unittest.TestCase):
    def test_restart_by_name_quotes_path_and_requests_async_start(self) -> None:
        client = CuttleApiClient(
            server_host="example.com",
            server_port=8000,
            auth_token="secret-token",
            user_id="alice",
        )
        instance = make_instance(instance_name="demo/name")

        with patch.object(
            CuttleApiClient,
            "_request_json",
            return_value=instance.model_dump(mode="json"),
        ) as request_json:
            restarted = client.restart_instance_by_name(
                "demo/name",
                async_start=True,
            )

        self.assertEqual(restarted, instance)
        request_json.assert_called_once_with(
            "POST",
            "/v1/instances/by-name/demo%2Fname/restart?async_start=true",
        )


class CliConfigTests(unittest.TestCase):
    def test_default_config_path_uses_platformdirs(self) -> None:
        config_dir = Path("/config")
        with patch("cuttle_cli.config.user_config_path", return_value=config_dir) as path:
            self.assertEqual(default_config_path(), config_dir / "config.toml")
        path.assert_called_once_with("cuttle_cli", appauthor=False)

    def test_default_state_dir_uses_platformdirs(self) -> None:
        state_dir = Path("/state")
        with patch("cuttle_cli.config.user_state_path", return_value=state_dir) as path:
            self.assertEqual(default_state_dir(), state_dir)
        path.assert_called_once_with("cuttle_cli", appauthor=False)

    def test_load_cli_settings_reads_default_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.toml"
            config_path.write_text(
                'server_host = "example.com"\n'
                "server_port = 9999\n"
                'auth_token = "secret"\n'
                'user_id = "alice"\n',
                encoding="utf-8",
            )
            with patch("cuttle_cli.config.default_config_path", return_value=config_path):
                settings = load_cli_settings()

        self.assertEqual(settings.server_host, "example.com")
        self.assertEqual(settings.server_port, 9999)
        self.assertEqual(settings.auth_token, "secret")
        self.assertEqual(settings.user_id, "alice")

    def test_load_cli_settings_applies_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.toml"
            config_path.write_text(
                'server_host = "example.com"\n'
                "server_port = 9999\n"
                'auth_token = "secret"\n'
                'user_id = "alice"\n',
                encoding="utf-8",
            )
            settings = load_cli_settings(
                server_host="localhost",
                server_port=8001,
                auth_token="override-token",
                user_id="bob",
                config_path=config_path,
            )

        self.assertEqual(settings.server_host, "localhost")
        self.assertEqual(settings.server_port, 8001)
        self.assertEqual(settings.auth_token, "override-token")
        self.assertEqual(settings.user_id, "bob")


class CuttleClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = make_settings()
        self.api = Mock(spec=CuttleApiClient)
        with patch(
            "cuttle_cli.client.CuttleApiClient.from_settings",
            return_value=self.api,
        ):
            self.client = CuttleClient.from_settings(self.settings)

    def test_client_is_exported_and_can_load_config(self) -> None:
        self.assertIs(ExportedCuttleClient, CuttleClient)
        api = Mock(spec=CuttleApiClient)
        with patch("cuttle_cli.client.load_cli_settings", return_value=self.settings) as load, patch(
            "cuttle_cli.client.CuttleApiClient.from_settings", return_value=api
        ):
            client = CuttleClient.from_config(config_path=Path("/config.toml"))

        load.assert_called_once_with(
            server_host=None,
            server_port=None,
            auth_token=None,
            user_id=None,
            config_path=Path("/config.toml"),
        )
        self.assertIs(client._api, api)
        self.assertEqual(repr(client), "CuttleClient()")

    def test_start_builds_request_and_returns_rich_result(self) -> None:
        instance = make_instance()
        logs = make_logs(start_log="ready\n")
        self.api.start_instance.return_value = CreateInstanceResponse(instance=instance)
        self.api.get_instance_logs.return_value = logs
        self.api.adb_target.return_value = "example.com:6520"

        with patch("cuttle_cli.client.ensure_managed_daemon_running") as ensure_daemon:
            result = self.client.start(
                "phone",
                name="demo",
                cpus=6,
                selinux=False,
                load_apps=False,
                unmanaged=True,
            )

        request_body = self.api.start_instance.call_args.args[0]
        self.assertIsInstance(request_body, CreateInstanceRequest)
        self.assertEqual(request_body.template_name, "phone")
        self.assertEqual(request_body.instance_name, "demo")
        self.assertEqual(request_body.overrides.cpus, 6)
        self.assertFalse(request_body.overrides.selinux)
        self.assertFalse(request_body.overrides.load_apps)
        self.assertTrue(request_body.overrides.unmanaged)
        self.assertTrue(self.api.start_instance.call_args.kwargs["async_start"])
        self.assertEqual(result, StartResult(instance, logs, "example.com:6520"))
        self.assertTrue(result.is_active)
        ensure_daemon.assert_called_once_with(self.settings)

    def test_start_progress_emits_only_new_log_text(self) -> None:
        starting = make_instance(state=InstanceState.STARTING)
        active = make_instance()
        self.api.start_instance.return_value = CreateInstanceResponse(instance=starting)
        self.api.get_instance_logs.side_effect = [
            make_logs(state=InstanceState.STARTING, start_log="booting\n"),
            make_logs(start_log="booting\ndone\n"),
        ]
        self.api.get_instance.return_value = active
        self.api.adb_target.return_value = "example.com:6520"
        chunks: list[str] = []

        with patch("cuttle_cli.client.ensure_managed_daemon_running"), patch(
            "cuttle_cli.client.time.sleep"
        ):
            result = self.client._start_with_progress(
                "phone",
                on_log_chunk=chunks.append,
            )

        self.assertEqual(chunks, ["booting\n", "done\n"])
        self.assertTrue(result.is_active)
        self.api.get_instance.assert_called_once_with("inst-1")
        request_body = self.api.start_instance.call_args.args[0]
        self.assertFalse(request_body.overrides.unmanaged)

    def test_start_returns_non_active_terminal_state_with_diagnostics(self) -> None:
        crashed = make_instance(
            state=InstanceState.CRASHED,
            failure_reason="adb timed out",
        )
        logs = make_logs(
            state=InstanceState.CRASHED,
            kernel_log="kernel failure\n",
        )
        self.api.start_instance.return_value = CreateInstanceResponse(instance=crashed)
        self.api.get_instance_logs.return_value = logs
        self.api.adb_target.return_value = None

        with patch("cuttle_cli.client.ensure_managed_daemon_running"):
            result = self.client.start("phone")

        self.assertFalse(result.is_active)
        self.assertEqual(result.logs.kernel_log, "kernel failure\n")

    def test_restart_waits_for_startup_and_refreshes_same_adb_target(self) -> None:
        starting = make_instance(state=InstanceState.STARTING)
        active = make_instance()
        logs = make_logs(
            start_log="booting\ndone\n",
            stop_log="restart stop warning: stop failed\n",
        )
        self.api.restart_instance_by_name.return_value = starting
        self.api.get_instance.return_value = active
        self.api.get_instance_logs.side_effect = [
            make_logs(state=InstanceState.STARTING, start_log="booting\n"),
            logs,
        ]
        self.api.adb_target.return_value = "example.com:6520"
        chunks: list[str] = []

        with patch(
            "cuttle_cli.client.ensure_managed_daemon_running"
        ) as ensure_daemon, patch(
            "cuttle_cli.client.refresh_adb_connection"
        ) as refresh, patch(
            "cuttle_cli.client.time.sleep"
        ):
            result = self.client._restart_with_progress(
                "demo",
                on_log_chunk=chunks.append,
            )

        self.api.restart_instance_by_name.assert_called_once_with(
            "demo",
            async_start=True,
        )
        self.assertEqual(result, StartResult(active, logs, "example.com:6520"))
        self.assertEqual(chunks, ["booting\n", "done\n"])
        ensure_daemon.assert_called_once_with(self.settings)
        refresh.assert_called_once_with("example.com:6520")

    def test_restart_returns_failed_start_without_refreshing_adb(self) -> None:
        crashed = make_instance(
            state=InstanceState.CRASHED,
            failure_reason="port remains in use",
        )
        logs = make_logs(
            state=InstanceState.CRASHED,
            failure_reason="port remains in use",
            stop_log="restart stop warning: stop failed\n",
        )
        self.api.restart_instance_by_name.return_value = crashed
        self.api.get_instance_logs.return_value = logs
        self.api.adb_target.return_value = "example.com:6520"

        with patch("cuttle_cli.client.ensure_managed_daemon_running"), patch(
            "cuttle_cli.client.refresh_adb_connection"
        ) as refresh:
            result = self.client.restart("demo")

        self.assertFalse(result.is_active)
        self.assertEqual(result.logs.stop_log, "restart stop warning: stop failed\n")
        refresh.assert_not_called()

    def test_restart_does_not_refresh_unmanaged_adb_target(self) -> None:
        active = make_instance(unmanaged=True)
        self.api.restart_instance_by_name.return_value = active
        self.api.get_instance_logs.return_value = make_logs()
        self.api.adb_target.return_value = "example.com:6520"

        with patch("cuttle_cli.client.ensure_managed_daemon_running"), patch(
            "cuttle_cli.client.refresh_adb_connection"
        ) as refresh:
            result = self.client.restart("demo")

        self.assertTrue(result.is_active)
        self.assertTrue(result.instance.unmanaged)
        refresh.assert_not_called()

    def test_restart_requires_active_instance_to_expose_adb_target(self) -> None:
        active = make_instance(adb_port=None)
        self.api.restart_instance_by_name.return_value = active
        self.api.get_instance_logs.return_value = make_logs()
        self.api.adb_target.return_value = None

        with patch("cuttle_cli.client.ensure_managed_daemon_running"):
            with self.assertRaisesRegex(CliError, "does not expose an ADB target"):
                self.client.restart("demo")

    def test_restart_reports_active_instance_when_adb_refresh_fails(self) -> None:
        active = make_instance()
        self.api.restart_instance_by_name.return_value = active
        self.api.get_instance_logs.return_value = make_logs(
            stop_log="restart stop warning: stop failed\n"
        )
        self.api.adb_target.return_value = "example.com:6520"

        with patch("cuttle_cli.client.ensure_managed_daemon_running"), patch(
            "cuttle_cli.client.refresh_adb_connection",
            side_effect=CliError("failed to refresh ADB connection"),
        ):
            with self.assertRaisesRegex(
                CliError,
                "is active at example.com:6520.*previous stop warning",
            ):
                self.client.restart("demo")

    def test_list_instances_filters_terminal_states_and_can_include_them(self) -> None:
        running = make_instance()
        stopped = make_instance(
            instance_id="inst-2",
            instance_name="done",
            state=InstanceState.STOPPED,
        )
        self.api.list_instances.return_value = InstanceListResponse(
            instances=[running, stopped]
        )

        with patch("cuttle_cli.client.ensure_managed_daemon_running") as ensure_daemon:
            visible = self.client.list_instances()
            all_instances = self.client.list_instances(include_terminal=True)

        self.assertEqual(visible, [running])
        self.assertEqual(all_instances, [running, stopped])
        self.assertEqual(ensure_daemon.call_count, 2)

    def test_logs_resolves_name_and_rejects_ambiguous_matches(self) -> None:
        logs = make_logs()
        self.api.get_instance_logs.side_effect = [
            CliError("server returned 404: missing"),
            logs,
        ]
        self.api.list_instances.return_value = InstanceListResponse(
            instances=[make_instance()]
        )
        self.assertEqual(self.client.logs("demo"), logs)
        self.api.get_instance_logs.assert_has_calls([call("demo"), call("inst-1")])

        self.api.get_instance_logs.reset_mock()
        self.api.get_instance_logs.side_effect = CliError("server returned 404: missing")
        self.api.list_instances.return_value = InstanceListResponse(
            instances=[
                make_instance(instance_id="inst-1"),
                make_instance(instance_id="inst-2"),
            ]
        )
        with self.assertRaisesRegex(CliError, "multiple visible instances"):
            self.client.logs("demo")

    def test_stop_and_bulk_stop_delegate_with_partial_results(self) -> None:
        alice = make_instance()
        bob = make_instance(instance_id="inst-2", instance_name="bob", owner_id="bob")
        terminal = make_instance(
            instance_id="inst-3",
            instance_name="done",
            state=InstanceState.STOPPED,
        )
        self.api.stop_instance_by_name.return_value = alice
        self.api.list_instances.return_value = InstanceListResponse(
            instances=[alice, bob, terminal]
        )
        self.api.stop_instance.side_effect = [alice, CliError("stop failed")]

        with patch("cuttle_cli.client.ensure_managed_daemon_running"):
            self.assertEqual(self.client.stop("demo"), alice)
            result = self.client.stop_all()

        self.api.stop_instance_by_name.assert_called_once_with("demo")
        self.assertEqual(result.stopped, (alice,))
        self.assertEqual(result.failures, (StopFailure(bob, "stop failed"),))
        self.assertFalse(result.is_successful)
        self.assertEqual(
            [stop_call.args[0] for stop_call in self.api.stop_instance.call_args_list],
            ["inst-1", "inst-2"],
        )

    def test_stop_all_user_only_targets_matching_visible_owner(self) -> None:
        alice = make_instance()
        bob = make_instance(instance_id="inst-2", instance_name="bob", owner_id="bob")
        self.api.list_instances.return_value = InstanceListResponse(
            instances=[alice, bob]
        )
        self.api.stop_instance.return_value = bob

        with patch("cuttle_cli.client.ensure_managed_daemon_running"):
            result = self.client.stop_all_user("bob")

        self.assertEqual(result.stopped, (bob,))
        self.api.stop_instance.assert_called_once_with("inst-2")

    def test_template_methods_return_domain_models(self) -> None:
        summary = TemplateSummary(template_name="phone", cpus=4, selinux=False)
        template = make_template()
        self.api.list_templates.return_value = TemplateListResponse(templates=[summary])
        self.api.get_template.return_value = template

        self.assertEqual(self.client.list_templates(), [summary])
        self.assertEqual(self.client.show_template("phone"), template)

    def test_daemon_methods_delegate_and_sync_rejects_running_daemon(self) -> None:
        stopped_status = DaemonStatus(running=False, stale=False, metadata=None)
        running_status = DaemonStatus(running=True, stale=False, metadata=None)
        with patch("cuttle_cli.client.start_managed_daemon") as start, patch(
            "cuttle_cli.client.stop_managed_daemon", return_value=True
        ) as stop, patch(
            "cuttle_cli.client.get_daemon_status", return_value=stopped_status
        ) as status, patch(
            "cuttle_cli.client.sync_managed_daemon_once",
            return_value=["example.com:6520"],
        ) as sync:
            self.client.daemon_start()
            self.assertTrue(self.client.daemon_stop())
            self.assertEqual(self.client.daemon_status(), stopped_status)
            self.assertEqual(self.client.daemon_sync(), ["example.com:6520"])

        start.assert_called_once_with(self.settings)
        stop.assert_called_once_with()
        self.assertEqual(status.call_count, 2)
        sync.assert_called_once_with(self.settings)

        with patch("cuttle_cli.client.get_daemon_status", return_value=running_status):
            with self.assertRaisesRegex(CliError, "daemon is already running"):
                self.client.daemon_sync()


class CliCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def invoke(self, client: Mock, arguments: list[str]) -> Result:
        with patch("cuttle_cli.main.CuttleClient.from_config", return_value=client):
            return self.runner.invoke(app, arguments)

    def test_help_does_not_require_config(self) -> None:
        result = self.runner.invoke(app, ["--help"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("daemon", result.output)

    def test_start_delegates_and_streams_logs(self) -> None:
        client = Mock(spec=CuttleClient)
        instance = make_instance()
        logs = make_logs(start_log="booting\ndone\n")

        def start_with_progress(
            template_name: str,
            *,
            name: str | None,
            cpus: int | None,
            selinux: bool | None,
            load_apps: bool | None,
            unmanaged: bool,
            on_log_chunk: Callable[[str], None],
        ) -> StartResult:
            self.assertEqual(template_name, "phone")
            self.assertEqual(
                (name, cpus, selinux, load_apps, unmanaged),
                ("demo", 6, None, False, True),
            )
            on_log_chunk("booting\n")
            on_log_chunk("done\n")
            return StartResult(instance, logs, "example.com:6520")

        client._start_with_progress.side_effect = start_with_progress
        result = self.invoke(
            client,
            [
                "start",
                "phone",
                "--name",
                "demo",
                "--cpus",
                "6",
                "--no-load-apps",
                "--unmanaged",
            ],
        )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("booting\ndone\n", result.output)
        self.assertIn("adb=example.com:6520", result.output)

    def test_failed_start_prints_diagnostics_and_exits_nonzero(self) -> None:
        client = Mock(spec=CuttleClient)
        crashed = make_instance(
            state=InstanceState.CRASHED,
            failure_reason="adb timed out",
        )
        logs = make_logs(
            state=InstanceState.CRASHED,
            kernel_log="kernel failure\n",
            launcher_log="launcher failure\n",
            logcat="logcat failure\n",
        )
        client._start_with_progress.return_value = StartResult(crashed, logs, None)

        result = self.invoke(client, ["start", "phone"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("== kernel.log ==", result.output)
        self.assertIn("launcher failure", result.output)
        self.assertIn("failed to start demo: adb timed out", result.output)

    def test_unexpected_stopped_start_exits_nonzero(self) -> None:
        client = Mock(spec=CuttleClient)
        stopped = make_instance(state=InstanceState.STOPPED)
        client._start_with_progress.return_value = StartResult(
            stopped,
            make_logs(state=InstanceState.STOPPED),
            None,
        )

        result = self.invoke(client, ["start", "phone"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("failed to start demo: startup failed", result.output)

    def test_restart_streams_logs_and_surfaces_nonfatal_stop_warning(self) -> None:
        client = Mock(spec=CuttleClient)
        active = make_instance()
        logs = make_logs(
            start_log="booting\ndone\n",
            stop_log="restart stop warning: stop failed\n",
        )

        def restart_with_progress(
            instance_name: str,
            *,
            on_log_chunk: Callable[[str], None],
        ) -> StartResult:
            self.assertEqual(instance_name, "demo")
            on_log_chunk("booting\n")
            on_log_chunk("done\n")
            return StartResult(active, logs, "example.com:6520")

        client._restart_with_progress.side_effect = restart_with_progress

        result = self.invoke(client, ["restart", "demo"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("booting\ndone\n", result.output)
        self.assertIn("restart stop warning: stop failed", result.output)
        self.assertIn("restarted demo (inst-1)", result.output)
        self.assertIn("adb=example.com:6520", result.output)

    def test_failed_restart_prints_stop_warning_and_diagnostics(self) -> None:
        client = Mock(spec=CuttleClient)
        crashed = make_instance(
            state=InstanceState.CRASHED,
            failure_reason="port remains in use",
        )
        client._restart_with_progress.return_value = StartResult(
            crashed,
            make_logs(
                state=InstanceState.CRASHED,
                stop_log="restart stop warning: stop failed\n",
                kernel_log="kernel failure\n",
            ),
            "example.com:6520",
        )

        result = self.invoke(client, ["restart", "demo"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("restart stop warning: stop failed", result.output)
        self.assertIn("kernel failure", result.output)
        self.assertIn("failed to restart demo: port remains in use", result.output)

    def test_logs_delegates_and_renders(self) -> None:
        client = Mock(spec=CuttleClient)
        client.logs.return_value = make_logs(start_log="booting\n", stop_log="stopped\n")

        result = self.invoke(client, ["logs", "demo"])

        self.assertEqual(result.exit_code, 0, result.output)
        client.logs.assert_called_once_with("demo")
        self.assertIn("== cvd start ==", result.output)
        self.assertIn("== cvd stop ==", result.output)

    def test_list_delegates_filter_choice_and_renders(self) -> None:
        client = Mock(spec=CuttleClient)
        instance = make_instance(instance_name="inst-1")
        client.list_instances.return_value = [instance]
        client.adb_target.return_value = "example.com:6520"

        default_result = self.invoke(client, ["list"])
        all_result = self.invoke(client, ["list", "--all"])

        self.assertEqual(default_result.exit_code, 0, default_result.output)
        self.assertEqual(all_result.exit_code, 0, all_result.output)
        client.list_instances.assert_has_calls(
            [call(include_terminal=False), call(include_terminal=True)]
        )
        self.assertIn("example.com:6520", default_result.output)

    def test_stop_modes_delegate_and_render_batch_failures(self) -> None:
        client = Mock(spec=CuttleClient)
        instance = make_instance()
        client.stop.return_value = instance

        single = self.invoke(client, ["stop", "demo"])

        self.assertEqual(single.exit_code, 0, single.output)
        client.stop.assert_called_once_with("demo")

        failure_instance = make_instance(instance_id="inst-2", instance_name="other")
        client.stop_all.return_value = StopManyResult(
            stopped=(instance,),
            failures=(StopFailure(failure_instance, "stop failed"),),
        )
        bulk = self.invoke(client, ["stop", "--stop-all"])

        self.assertEqual(bulk.exit_code, 1, bulk.output)
        self.assertIn("stopped demo (inst-1)", bulk.output)
        self.assertIn("failed to stop other (inst-2): stop failed", bulk.output)

        client.stop_all_user.return_value = StopManyResult(stopped=(), failures=())
        by_user = self.invoke(client, ["stop", "--stop-all-user", "bob"])
        self.assertEqual(by_user.exit_code, 0, by_user.output)
        self.assertEqual(by_user.output.strip(), "No matching running instances.")
        client.stop_all_user.assert_called_once_with("bob")

    def test_stop_rejects_multiple_modes_before_calling_client(self) -> None:
        client = Mock(spec=CuttleClient)
        result = self.invoke(client, ["stop", "demo", "--stop-all"])

        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("specify exactly one", result.output)
        client.stop.assert_not_called()
        client.stop_all.assert_not_called()

    def test_template_commands_delegate_and_render(self) -> None:
        client = Mock(spec=CuttleClient)
        client.list_templates.return_value = [
            TemplateSummary(
                template_name="phone",
                cpus=4,
                selinux=False,
                command_mode=CvdCommandMode.LEGACY,
            )
        ]
        client.show_template.return_value = make_template()

        list_result = self.invoke(client, ["templates", "list"])
        show_result = self.invoke(client, ["templates", "show", "phone"])

        self.assertEqual(list_result.exit_code, 0, list_result.output)
        self.assertEqual(show_result.exit_code, 0, show_result.output)
        client.list_templates.assert_called_once_with()
        client.show_template.assert_called_once_with("phone")
        self.assertIn("command_mode=legacy", list_result.output)
        self.assertIn("runtime_root: /cf", show_result.output)

    def test_daemon_commands_delegate(self) -> None:
        client = Mock(spec=CuttleClient)
        client.daemon_stop.return_value = True
        client.daemon_status.return_value = DaemonStatus(
            running=False,
            stale=False,
            metadata=None,
        )
        client.daemon_sync.return_value = ["example.com:6520"]

        start_result = self.invoke(client, ["daemon", "start"])
        stop_result = self.invoke(client, ["daemon", "stop"])
        status_result = self.invoke(client, ["daemon", "status"])
        sync_result = self.invoke(client, ["daemon", "sync"])

        self.assertEqual(start_result.output.strip(), "daemon started")
        self.assertEqual(stop_result.output.strip(), "daemon stopped")
        self.assertEqual(status_result.output.strip(), "stopped")
        self.assertEqual(sync_result.output.strip(), "synced 1 endpoints")
        client.daemon_start.assert_called_once_with()
        client.daemon_stop.assert_called_once_with()
        client.daemon_status.assert_called_once_with()
        client.daemon_sync.assert_called_once_with()


class DaemonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_sync_reconciles_adb_endpoints(self) -> None:
        mock_client = Mock(spec=CuttleApiClient)
        mock_client.server_host = "example.com"
        mock_client.adb_target.side_effect = lambda instance: (
            None if instance.adb_port is None else f"example.com:{instance.adb_port}"
        )
        mock_client.list_instances.return_value = InstanceListResponse(
            instances=[
                make_instance(),
                make_instance(
                    instance_id="inst-2",
                    instance_name="external",
                    adb_port=6521,
                    unmanaged=True,
                ),
            ]
        )

        with patch("cuttle_cli.daemon.default_state_dir", return_value=self.root), patch(
            "cuttle_cli.daemon.subprocess.run"
        ) as run:
            run.return_value.returncode = 0
            endpoints = sync_managed_daemon_once_with_client(mock_client)
            mock_client.list_instances.return_value = InstanceListResponse(instances=[])
            endpoints = sync_managed_daemon_once_with_client(mock_client)

        self.assertEqual(
            [adb_call.args[0] for adb_call in run.call_args_list],
            [
                ["adb", "connect", "example.com:6520"],
                ["adb", "disconnect", "example.com:6520"],
            ],
        )
        self.assertEqual(endpoints, [])

    def test_refresh_adb_connection_connects_existing_endpoint(self) -> None:
        with patch("cuttle_cli.daemon.subprocess.run") as run:
            run.return_value.returncode = 0
            refresh_adb_connection("example.com:6520")

        run.assert_called_once_with(
            ["adb", "connect", "example.com:6520"],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_sync_relinquishes_unmanaged_endpoint_without_disconnecting(self) -> None:
        mock_client = Mock(spec=CuttleApiClient)
        mock_client.adb_target.return_value = "example.com:6520"
        mock_client.list_instances.return_value = InstanceListResponse(
            instances=[make_instance(unmanaged=True)]
        )
        (self.root / "owned_endpoints.json").write_text(
            '{"endpoints":["example.com:6520"]}',
            encoding="utf-8",
        )

        with patch("cuttle_cli.daemon.default_state_dir", return_value=self.root), patch(
            "cuttle_cli.daemon.subprocess.run"
        ) as run:
            endpoints = sync_managed_daemon_once_with_client(mock_client)

        self.assertEqual(endpoints, [])
        run.assert_not_called()

    def test_refresh_adb_connection_reports_failure(self) -> None:
        with patch("cuttle_cli.daemon.subprocess.run") as run:
            run.return_value.returncode = 1
            run.return_value.stderr = "connection refused\n"
            run.return_value.stdout = ""
            with self.assertRaisesRegex(CliError, "connection refused"):
                refresh_adb_connection("example.com:6520")

    def test_status_reads_metadata_and_stop_cleans_files(self) -> None:
        metadata = DaemonMetadata(
            pid=4242,
            server_host="example.com",
            server_port=8000,
            user_id="alice",
            auth_token_sha256="0" * 64,
        )
        (self.root / "daemon.json").write_text(
            metadata.model_dump_json(), encoding="utf-8"
        )
        (self.root / "daemon.pid").write_text("4242\n", encoding="utf-8")
        (self.root / "owned_endpoints.json").write_text(
            '{"endpoints":["example.com:6520"]}',
            encoding="utf-8",
        )

        with patch("cuttle_cli.daemon.default_state_dir", return_value=self.root), patch(
            "cuttle_cli.daemon.os.kill",
            side_effect=[None, None, None, ProcessLookupError()],
        ), patch("cuttle_cli.daemon.subprocess.run") as run:
            run.return_value.returncode = 0
            status = get_daemon_status()
            stopped = stop_managed_daemon()

        self.assertTrue(status.running)
        self.assertIsNotNone(status.metadata)
        assert status.metadata is not None
        self.assertEqual(render_daemon_identity(status.metadata), "alice@example.com:8000")
        self.assertTrue(stopped)
        self.assertEqual(
            run.call_args.args[0], ["adb", "disconnect", "example.com:6520"]
        )
        self.assertFalse((self.root / "daemon.json").exists())
        self.assertFalse((self.root / "daemon.pid").exists())
