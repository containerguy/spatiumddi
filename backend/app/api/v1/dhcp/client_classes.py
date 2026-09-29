"""DHCP client class CRUD — group-centric."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.v1.dhcp._audit import write_audit
from app.api.v1.dhcp.scopes import validate_dhcp_options
from app.core.agent_wake import collect_wake, dhcp_group_channel
from app.core.permissions import require_resource_permission
from app.models.dhcp import DHCPClientClass, DHCPServerGroup
from app.services.dhcp.option_validation import normalize_options, validate_class_test

# Which Kea daemons the class renders into (#1229). ``dual`` sends each option
# to whichever family it is valid in (#1295).
ClassFamily = Literal["ipv4", "ipv6", "dual"]

router = APIRouter(
    tags=["dhcp"], dependencies=[Depends(require_resource_permission("dhcp_client_class"))]
)


class ClientClassCreate(BaseModel):
    name: str
    match_expression: str = ""
    description: str = ""
    address_family: ClassFamily = "ipv4"
    options: dict[str, Any] = {}


class ClientClassUpdate(BaseModel):
    name: str | None = None
    match_expression: str | None = None
    description: str | None = None
    address_family: ClassFamily | None = None
    options: dict[str, Any] | None = None


class ClientClassResponse(BaseModel):
    id: uuid.UUID
    group_id: uuid.UUID
    name: str
    match_expression: str
    description: str
    address_family: str
    options: dict[str, Any]
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}


def _check_test(expression: str, family: str) -> None:
    try:
        validate_class_test(expression, family)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/server-groups/{group_id}/client-classes", response_model=list[ClientClassResponse])
async def list_classes(group_id: uuid.UUID, db: DB, _: CurrentUser) -> list[DHCPClientClass]:
    res = await db.execute(select(DHCPClientClass).where(DHCPClientClass.group_id == group_id))
    return list(res.scalars().all())


@router.post(
    "/server-groups/{group_id}/client-classes",
    response_model=ClientClassResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_class(
    group_id: uuid.UUID, body: ClientClassCreate, db: DB, user: SuperAdmin
) -> DHCPClientClass:
    grp = await db.get(DHCPServerGroup, group_id)
    if grp is None:
        raise HTTPException(status_code=404, detail="DHCP server group not found")
    existing = await db.execute(
        select(DHCPClientClass).where(
            DHCPClientClass.group_id == group_id, DHCPClientClass.name == body.name
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A client class with that name exists")
    _check_test(body.match_expression, body.address_family)
    body.options = normalize_options(body.options)
    validate_dhcp_options(body.options, address_family=body.address_family)
    cc = DHCPClientClass(group_id=group_id, **body.model_dump())
    db.add(cc)
    await db.flush()
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="dhcp_client_class",
        resource_id=str(cc.id),
        resource_display=cc.name,
        new_value=body.model_dump(mode="json"),
    )
    collect_wake(dhcp_group_channel(group_id))
    await db.commit()
    await db.refresh(cc)
    return cc


@router.put("/client-classes/{class_id}", response_model=ClientClassResponse)
async def update_class(
    class_id: uuid.UUID, body: ClientClassUpdate, db: DB, user: SuperAdmin
) -> DHCPClientClass:
    cc = await db.get(DHCPClientClass, class_id)
    if cc is None:
        raise HTTPException(status_code=404, detail="Client class not found")
    changes = body.model_dump(exclude_none=True)
    family = changes.get("address_family", cc.address_family)
    family_changed = family != cc.address_family
    if family_changed or "match_expression" in changes:
        _check_test(changes.get("match_expression", cc.match_expression), family)
    if "options" in changes or family_changed:
        # Validate only changed options (#597, #1228) vs the stored value —
        # unless the family changed, which makes every option new to it.
        options = (
            normalize_options(changes["options"]) if "options" in changes else cc.options or {}
        )
        validate_dhcp_options(
            options,
            address_family=family,
            previous=None if family_changed else cc.options or {},
        )
        if "options" in changes:
            changes["options"] = options
    for k, v in changes.items():
        setattr(cc, k, v)
    write_audit(
        db,
        user=user,
        action="update",
        resource_type="dhcp_client_class",
        resource_id=str(cc.id),
        resource_display=cc.name,
        changed_fields=list(changes.keys()),
        new_value=body.model_dump(mode="json", exclude_none=True),
    )
    collect_wake(dhcp_group_channel(cc.group_id))
    await db.commit()
    await db.refresh(cc)
    return cc


@router.delete("/client-classes/{class_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_class(class_id: uuid.UUID, db: DB, user: SuperAdmin) -> None:
    cc = await db.get(DHCPClientClass, class_id)
    if cc is None:
        raise HTTPException(status_code=404, detail="Client class not found")
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="dhcp_client_class",
        resource_id=str(cc.id),
        resource_display=cc.name,
    )
    collect_wake(dhcp_group_channel(cc.group_id))
    await db.delete(cc)
    await db.commit()
