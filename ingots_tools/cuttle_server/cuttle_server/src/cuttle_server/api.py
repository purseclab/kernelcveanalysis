import asyncio
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated

from cuttle_types import (
    CreateInstanceRequest,
    CreateInstanceResponse,
    InstanceListResponse,
    InstanceView,
    RenewLeaseRequest,
    TemplateListResponse,
    TemplateView,
)
from fastapi import Depends, FastAPI, Header, HTTPException, status

from .config import CuttlefishSettings
from .cvd_cli import CuttlefishCli
from .db import InstanceDb
from .server_manager import (
    AuthorizationError,
    CapacityError,
    CuttlefishServerManager,
    InstanceError,
    NotFoundError,
)

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RequestIdentity:
    user_id: str
    is_admin: bool


def validate_authorization_header(
    authorization: str | None, expected_token: str
) -> None:
    expected = f"Bearer {expected_token}"
    if authorization != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing authorization token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def validate_user_id_header(user_id: str | None) -> str:
    normalized = (user_id or "").strip()
    if not normalized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing or invalid X-User-Id header",
        )
    return normalized


def build_request_identity(
    authorization: str | None,
    user_id: str | None,
    expected_token: str,
    admin_user_id: str,
) -> RequestIdentity:
    validate_authorization_header(authorization, expected_token)
    normalized_user_id = validate_user_id_header(user_id)
    return RequestIdentity(
        user_id=normalized_user_id,
        is_admin=normalized_user_id == admin_user_id,
    )


async def reconcile_expired_instances_periodically(
    server_manager: CuttlefishServerManager,
    interval_sec: float,
    stop_event: asyncio.Event,
) -> None:
    while True:
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_sec)
            return
        except TimeoutError:
            try:
                await asyncio.to_thread(server_manager.reconcile_expired_instances)
            except Exception:
                LOGGER.exception("periodic expired-instance reconciliation failed")


def create_app(settings: CuttlefishSettings) -> FastAPI:
    db = InstanceDb(settings.database_path)
    cli = CuttlefishCli()
    server_manager = CuttlefishServerManager(settings, db, cli)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        server_manager.initialize()
        await asyncio.to_thread(server_manager.reconcile_expired_instances)
        stop_event = asyncio.Event()
        reconcile_task = asyncio.create_task(
            reconcile_expired_instances_periodically(
                server_manager,
                settings.reconcile_interval_sec,
                stop_event,
            )
        )
        try:
            yield
        finally:
            stop_event.set()
            await reconcile_task
            db.close()

    app = FastAPI(
        title="Cuttlefish Control Plane",
        version="0.1.0",
        lifespan=lifespan,
    )

    def require_identity(
        authorization: Annotated[
            str | None, Header(alias="Authorization")
        ] = None,
        user_id: Annotated[str | None, Header(alias="X-User-Id")] = None,
    ) -> RequestIdentity:
        return build_request_identity(
            authorization,
            user_id,
            settings.auth_token,
            settings.admin_user_id,
        )

    @app.post(
        "/v1/instances",
        response_model=CreateInstanceResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def create_instance(
        request: CreateInstanceRequest,
        identity: Annotated[RequestIdentity, Depends(require_identity)],
    ) -> CreateInstanceResponse:
        try:
            return server_manager.create_instance(identity.user_id, request)
        except CapacityError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail=str(exc)
            ) from exc
        except InstanceError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
            ) from exc

    @app.get("/v1/instances", response_model=InstanceListResponse)
    def list_instances(
        identity: Annotated[RequestIdentity, Depends(require_identity)],
    ) -> InstanceListResponse:
        return server_manager.list_instances(identity.user_id, identity.is_admin)

    @app.get("/v1/templates", response_model=TemplateListResponse)
    def list_templates(
        _: Annotated[RequestIdentity, Depends(require_identity)],
    ) -> TemplateListResponse:
        return server_manager.list_templates()

    @app.get("/v1/templates/{template_name}", response_model=TemplateView)
    def get_template(
        template_name: str,
        _: Annotated[RequestIdentity, Depends(require_identity)],
    ) -> TemplateView:
        try:
            return server_manager.get_template(template_name)
        except NotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
            ) from exc

    @app.get("/v1/instances/{instance_id}", response_model=InstanceView)
    def get_instance(
        instance_id: str,
        identity: Annotated[RequestIdentity, Depends(require_identity)],
    ) -> InstanceView:
        try:
            return server_manager.get_instance(
                identity.user_id,
                identity.is_admin,
                instance_id,
            )
        except NotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
            ) from exc
        except AuthorizationError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)
            ) from exc

    @app.post("/v1/instances/{instance_id}/renew", response_model=InstanceView)
    def renew_instance(
        instance_id: str,
        request: RenewLeaseRequest,
        identity: Annotated[RequestIdentity, Depends(require_identity)],
    ) -> InstanceView:
        try:
            return server_manager.renew_lease(
                identity.user_id,
                identity.is_admin,
                instance_id,
                request,
            )
        except NotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
            ) from exc
        except AuthorizationError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)
            ) from exc

    @app.post("/v1/instances/by-name/{instance_name}/stop", response_model=InstanceView)
    def stop_instance_by_name(
        instance_name: str,
        identity: Annotated[RequestIdentity, Depends(require_identity)],
    ) -> InstanceView:
        try:
            return server_manager.stop_instance_by_name(
                identity.user_id,
                identity.is_admin,
                instance_name,
            )
        except NotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
            ) from exc
        except AuthorizationError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)
            ) from exc
        except InstanceError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
            ) from exc

    @app.post("/v1/instances/{instance_id}/stop", response_model=InstanceView)
    def stop_instance(
        instance_id: str,
        identity: Annotated[RequestIdentity, Depends(require_identity)],
    ) -> InstanceView:
        try:
            return server_manager.stop_instance(
                identity.user_id,
                identity.is_admin,
                instance_id,
            )
        except NotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
            ) from exc
        except AuthorizationError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)
            ) from exc
        except InstanceError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
            ) from exc

    @app.post("/v1/admin/reconcile", response_model=InstanceListResponse)
    def reconcile_expired_instances(
        identity: Annotated[RequestIdentity, Depends(require_identity)],
    ) -> InstanceListResponse:
        if not identity.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="admin access required",
            )
        server_manager.reconcile_expired_instances()
        return server_manager.list_instances(identity.user_id, identity.is_admin)

    return app
