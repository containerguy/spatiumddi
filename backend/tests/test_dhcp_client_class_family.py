"""Client classes render only into the Kea daemons their family names (#1229, #1295).

Every operator client class used to go into both ``Dhcp4`` and ``Dhcp6``. A
test expression using ``pkt4`` / ``relay4`` makes kea-dhcp6 reject the whole
config ("pkt4 can only be used in DHCPv4" — measured, Kea 3.0.3), the mirror
image holds for ``pkt6`` / ``relay6``, and the agent then reverts the bundle
for BOTH daemons. And one options map cannot serve both: ``dns-servers`` is an
IPv4 list in Dhcp4 and an IPv6 one in Dhcp6.
"""

from __future__ import annotations

import importlib.util
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.drivers.dhcp.base import ClientClassDef, ConfigBundle, PoolDef, ScopeDef, ServerOptionsDef
from app.drivers.dhcp.kea import KeaDriver
from app.models.auth import User
from app.models.dhcp import DHCPClientClass, DHCPScope, DHCPServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dhcp.config_bundle import _client_class_def
from app.services.dhcp.option_validation import (
    options_for_family,
    validate_class_test,
    validate_options,
)

# ── The rules ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("expression", "family"),
    [
        ("pkt4.mac == 0x010203040506", "ipv6"),
        ("relay4[1].hex == 'x'", "ipv6"),
        ("pkt6.msgtype == 1", "ipv4"),
        ("relay6[0].peeraddr == 2001:db8::1", "ipv4"),
        ("pkt4.mac == 0x01", "dual"),
        ("pkt6.msgtype == 1", "dual"),
    ],
)
def test_a_test_the_familys_daemon_cannot_parse_is_refused(expression: str, family: str) -> None:
    with pytest.raises(ValueError, match="only kea-dhcp"):
        validate_class_test(expression, family)


@pytest.mark.parametrize(
    ("expression", "family"),
    [
        ("pkt4.mac == 0x01", "ipv4"),
        ("pkt6.msgtype == 1", "ipv6"),
        ("member('KNOWN')", "dual"),
        ("substring(option[60].hex,0,4) == 'MSFT'", "dual"),
        ("mypkt4thing == 'x'", "ipv6"),  # a word, not the token
        ("", "dual"),
    ],
)
def test_family_neutral_or_matching_tests_pass(expression: str, family: str) -> None:
    validate_class_test(expression, family)


def test_a_dual_class_takes_an_option_either_family_accepts() -> None:
    validate_options({"dns-servers": ["10.0.0.53"]}, address_family="dual")
    validate_options({"dns-servers": ["2001:db8::53"]}, address_family="dual")
    validate_options({"routers": ["10.0.0.1"], "code:43": "01"}, address_family="dual")
    with pytest.raises(ValueError, match="'dns-servers'"):
        validate_options({"dns-servers": ["bogus"]}, address_family="dual")


def test_a_dual_classs_options_go_where_each_is_valid() -> None:
    options = {
        "dns-servers": ["10.0.0.53"],
        "routers": ["10.0.0.1"],
        "domain-search": ["corp.example"],
        "code:43": "0104",
    }
    assert options_for_family(options, "ipv4") == options
    assert options_for_family(options, "ipv6") == {"domain-search": ["corp.example"]}
    v6 = {"dns-servers": ["2001:db8::53"]}
    assert options_for_family(v6, "ipv4") == {}
    assert options_for_family(v6, "ipv6") == v6


def test_the_bundle_carries_each_familys_options() -> None:
    def cls(family: str) -> ClientClassDef:
        return _client_class_def(
            DHCPClientClass(
                name="c",
                match_expression="",
                description="",
                address_family=family,
                options={"dns-servers": ["10.0.0.53"], "domain-search": ["corp.example"]},
            )
        )

    v4, v6, dual = cls("ipv4"), cls("ipv6"), cls("dual")
    assert (v4.in_family("ipv4"), v4.in_family("ipv6")) == (True, False)
    assert (v6.in_family("ipv4"), v6.in_family("ipv6")) == (False, True)
    assert (dual.in_family("ipv4"), dual.in_family("ipv6")) == (True, True)
    assert dual.options_v4 == {"dns-servers": ["10.0.0.53"], "domain-search": ["corp.example"]}
    assert dual.options_v6 == {"domain-search": ["corp.example"]}


# ── The control-plane render ─────────────────────────────────────────────────


def _render(classes: tuple[ClientClassDef, ...]) -> dict:
    bundle = ConfigBundle(
        server_id="00000000-0000-0000-0000-000000000000",
        server_name="kea-class-family",
        driver="kea",
        roles=(),
        options=ServerOptionsDef(options={}, lease_time=3600),
        scopes=(
            ScopeDef(
                subnet_cidr="10.29.0.0/24",
                pools=(PoolDef(start_ip="10.29.0.100", end_ip="10.29.0.200"),),
            ),
            ScopeDef(
                subnet_cidr="2001:db8:1229::/64",
                address_family="ipv6",
                pools=(PoolDef(start_ip="2001:db8:1229::10", end_ip="2001:db8:1229::20"),),
            ),
        ),
        client_classes=classes,
        generated_at=datetime.now(UTC),
    )
    return json.loads(KeaDriver().render_config(bundle))


def test_each_daemon_gets_only_its_classes() -> None:
    def cls(name: str, family: str, test: str, options: dict) -> ClientClassDef:
        return _client_class_def(
            DHCPClientClass(
                name=name,
                match_expression=test,
                description="",
                address_family=family,
                options=options,
            )
        )

    cfg = _render(
        (
            cls("relay82", "ipv4", "relay4[1].hex == 'sw1'", {"routers": ["10.29.0.1"]}),
            cls("v6only", "ipv6", "pkt6.msgtype == 1", {"dns-servers": ["2001:db8::53"]}),
            cls(
                "known",
                "dual",
                "member('KNOWN')",
                {"dns-servers": ["10.29.0.53"], "domain-search": ["corp.example"]},
            ),
        )
    )
    v4 = {c["name"]: c for c in cfg["Dhcp4"]["client-classes"]}
    v6 = {c["name"]: c for c in cfg["Dhcp6"]["client-classes"]}
    assert set(v4) == {"relay82", "known"}
    assert set(v6) == {"v6only", "known"}
    assert {o["name"] for o in v4["known"]["option-data"]} == {
        "domain-name-servers",
        "domain-search",
    }
    # The IPv4 DNS server stays out of Dhcp6 (#1295).
    assert v6["known"]["option-data"] == [{"name": "domain-search", "data": "corp.example"}]


def test_no_empty_client_classes_list_is_emitted() -> None:
    """Kea's parser refuses ``"client-classes": []`` as a syntax error."""
    cfg = _render(
        (
            _client_class_def(
                DHCPClientClass(
                    name="v4",
                    match_expression="pkt4.mac == 0x01",
                    description="",
                    address_family="ipv4",
                    options={},
                )
            ),
        )
    )
    assert "client-classes" not in cfg["Dhcp6"]


# ── API ──────────────────────────────────────────────────────────────────────


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def test_the_api_checks_the_test_and_options_against_the_family(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.commit()
    url = f"/api/v1/dhcp/server-groups/{grp.id}/client-classes"

    resp = await client.post(
        url,
        headers=h,
        json={"name": "r", "address_family": "dual", "match_expression": "relay4[1].hex == 'x'"},
    )
    assert resp.status_code == 422, resp.text
    assert "relay4" in resp.json()["detail"]

    resp = await client.post(
        url,
        headers=h,
        json={"name": "d", "address_family": "ipv6", "options": {"dns-servers": ["10.0.0.53"]}},
    )
    assert resp.status_code == 422, resp.text

    created = await client.post(
        url,
        headers=h,
        json={"name": "ok", "address_family": "ipv4", "options": {"routers": ["10.0.0.1"]}},
    )
    assert created.status_code == 201, created.text
    assert created.json()["address_family"] == "ipv4"

    # Moving it to IPv6 makes ``routers`` new to the class, so it is checked.
    moved = await client.put(
        f"/api/v1/dhcp/client-classes/{created.json()['id']}",
        headers=h,
        json={"address_family": "ipv6"},
    )
    assert moved.status_code == 422, moved.text
    assert "no DHCPv6 equivalent" in moved.json()["detail"]

    resp = await client.post(url, headers=h, json={"name": "x", "address_family": "ipv5"})
    assert resp.status_code == 422, resp.text


# ── Migration backfill ───────────────────────────────────────────────────────


def _migration_backfill() -> str:
    path = next(
        (Path(__file__).resolve().parents[1] / "alembic" / "versions").glob("c2f7a94e1d58_*.py")
    )
    spec = importlib.util.spec_from_file_location("m_c2f7a94e1d58", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return str(module.BACKFILL)


async def test_the_backfill_keeps_what_rendered_and_fixes_what_did_not(
    db_session: AsyncSession,
) -> None:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="2001:db8:1229::/48", name="b")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="2001:db8:1229::/64", name="s")
    with_v6 = DHCPServerGroup(name=f"v6-{uuid.uuid4().hex[:6]}")
    v4_only = DHCPServerGroup(name=f"v4-{uuid.uuid4().hex[:6]}")
    db_session.add_all([subnet, with_v6, v4_only])
    await db_session.flush()
    db_session.add(
        DHCPScope(subnet_id=subnet.id, group_id=with_v6.id, name="v6", address_family="ipv6")
    )
    rows = {
        "relay82": (with_v6, "relay4[1].hex == 'x'"),
        "pkt6": (with_v6, "pkt6.msgtype == 1"),
        "neutral_v6grp": (with_v6, "member('KNOWN')"),
        "neutral_v4grp": (v4_only, "member('KNOWN')"),
    }
    for name, (grp, test) in rows.items():
        db_session.add(DHCPClientClass(group_id=grp.id, name=name, match_expression=test))
    await db_session.flush()

    await db_session.execute(text(_migration_backfill()))
    got = dict(
        (await db_session.execute(select(DHCPClientClass.name, DHCPClientClass.address_family)))
        .tuples()
        .all()
    )
    assert got == {
        "relay82": "ipv4",
        "pkt6": "ipv6",
        "neutral_v6grp": "dual",
        "neutral_v4grp": "ipv4",
    }
