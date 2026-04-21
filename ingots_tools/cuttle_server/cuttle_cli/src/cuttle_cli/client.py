from __future__ import annotations

import json
from dataclasses import dataclass
from urllib import error, parse, request

from cuttle_types import (
    CreateInstanceRequest,
    CreateInstanceResponse,
    InstanceListResponse,
    InstanceView,
    TemplateListResponse,
    TemplateView,
)

from .config import CliSettings


class CliError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CuttleApiClient:
    server_host: str
    server_port: int
    auth_token: str
    user_id: str

    @classmethod
    def from_settings(cls, settings: CliSettings) -> "CuttleApiClient":
        return cls(
            server_host=settings.server_host,
            server_port=settings.server_port,
            auth_token=settings.auth_token,
            user_id=settings.user_id,
        )

    def start_instance(
        self, request_body: CreateInstanceRequest
    ) -> CreateInstanceResponse:
        data = self._request_json(
            "POST",
            "/v1/instances",
            request_body.model_dump(mode="json"),
        )
        return CreateInstanceResponse.model_validate(data)

    def list_instances(self) -> InstanceListResponse:
        data = self._request_json("GET", "/v1/instances")
        return InstanceListResponse.model_validate(data)

    def stop_instance_by_name(self, instance_name: str) -> InstanceView:
        quoted_name = parse.quote(instance_name, safe="")
        data = self._request_json(
            "POST",
            f"/v1/instances/by-name/{quoted_name}/stop",
        )
        return InstanceView.model_validate(data)

    def list_templates(self) -> TemplateListResponse:
        data = self._request_json("GET", "/v1/templates")
        return TemplateListResponse.model_validate(data)

    def get_template(self, template_name: str) -> TemplateView:
        quoted_name = parse.quote(template_name, safe="")
        data = self._request_json("GET", f"/v1/templates/{quoted_name}")
        return TemplateView.model_validate(data)

    def adb_target(self, instance: InstanceView) -> str | None:
        if instance.adb_port is None:
            return None
        return f"{self.server_host}:{instance.adb_port}"

    def _request_json(
        self,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
    ) -> dict[str, object]:
        url = f"http://{self.server_host}:{self.server_port}{path}"
        headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "X-User-Id": self.user_id,
        }
        body: bytes | None = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload).encode("utf-8")

        req = request.Request(url, data=body, headers=headers, method=method)
        try:
            with request.urlopen(req) as response:
                raw = response.read().decode("utf-8")
        except error.HTTPError as exc:
            raw_error = exc.read().decode("utf-8", errors="replace")
            detail = self._extract_error_detail(raw_error) or exc.reason
            raise CliError(f"server returned {exc.code}: {detail}") from exc
        except error.URLError as exc:
            raise CliError(f"failed to contact server: {exc.reason}") from exc

        if not raw:
            return {}
        return json.loads(raw)

    @staticmethod
    def _extract_error_detail(raw_error: str) -> str | None:
        try:
            payload = json.loads(raw_error)
        except json.JSONDecodeError:
            return raw_error or None
        detail = payload.get("detail")
        return str(detail) if detail is not None else raw_error or None
