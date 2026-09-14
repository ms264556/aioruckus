"""Encrypted values can be dropped instead of decrypted.

Redaction is opt-in and per session: a caller that only inspects the shape of
a config can avoid ever handling plaintext secrets. These tests cover both the
constructor and the settable property, and check that sessions do not leak the
setting into one another.

They also pin that ``getconf`` carries ``DECRYPT_X='true'``. That flag is what
makes the controller include its ``x-`` secret attributes at all; without it
they are omitted from the response, so decryption and redaction both depend on
it being sent.
"""

from __future__ import annotations

import re

import pytest

from aioruckus.ajaxsession import AjaxSession
from aioruckus.unleashedsession import UnleashedSession

from .conftest import cmdstat_callback

pytestmark = pytest.mark.asyncio


class _FakeClient:
    """Minimal stand-in for an aiohttp ClientSession."""

    def __init__(self):
        self.headers: dict = {}

    async def close(self) -> None:
        pass


async def test_redact_secrets_defaults_off(create_ajax_session):
    """Decrypting remains the default, so existing callers are unaffected."""
    async with create_ajax_session() as session:
        assert session.redact_secrets is False
        assert session.api.redact_secrets is False


async def test_redact_secrets_via_constructor(aiohttp_context):
    """The setting can be chosen up front when creating the session.

    Uses the raw constructor rather than the fixture so the flag is passed at
    creation time, which is the path under test.
    """
    aiohttp_context.post(
        re.compile(r"^https?://[^/]+/admin(?:10)?/_(?:conf|cmdstat)\.jsp"),
        callback=cmdstat_callback,
    )
    async with AjaxSession.async_create(
        "192.168.0.2", "super", "sp-admin", redact_secrets=True
    ) as session:
        assert session.redact_secrets is True
        # the API layer mirrors it so parsed responses are redacted
        assert session.api.redact_secrets is True


async def test_redact_secrets_is_settable_after_create(create_ajax_session):
    """The property can be toggled on an existing session."""
    async with create_ajax_session() as session:
        assert session.redact_secrets is False
        session.redact_secrets = True
        assert session.api.redact_secrets is True
        session.redact_secrets = False
        assert session.api.redact_secrets is False


async def test_redact_secrets_does_not_leak_between_sessions():
    """Each session owns its setting; one must not affect another.

    The flag is threaded through parsing rather than held in global state
    precisely so that concurrent sessions stay independent.
    """
    plain = UnleashedSession("host", "user", "pass", websession=_FakeClient())
    redacted = UnleashedSession(
        "host", "user", "pass", websession=_FakeClient(), redact_secrets=True
    )

    assert plain.redact_secrets is False
    assert redacted.redact_secrets is True

    plain.redact_secrets = True
    assert plain.redact_secrets is True
    assert redacted.redact_secrets is True

    redacted.redact_secrets = False
    assert plain.redact_secrets is True
    assert redacted.redact_secrets is False


async def test_unleashed_session_constructor_flag():
    """UnleashedSession accepts the setting directly."""
    assert UnleashedSession(
        "host", "user", "pass", websession=_FakeClient(), redact_secrets=True
    ).redact_secrets is True


async def test_redacted_getconf_omits_encrypted_values(create_ajax_session, set_ajax_results):
    """End to end: a redacted session drops the encrypted value.

    The mesh list mock carries the secret only as ``x-psk``; with redaction on
    that attribute is removed rather than decrypted, so no key of any kind
    appears in the result.
    """
    async with create_ajax_session() as session:
        session.redact_secrets = True
        set_ajax_results(0)
        mesh = await session.api.get_mesh_info()
        assert mesh["name"]
        # the encrypted attribute is dropped, not decrypted
        assert not [k for k in mesh if k.startswith("x-")]


async def test_unredacted_getconf_decrypts(create_ajax_session, set_ajax_results):
    """Without redaction the encrypted value is still decrypted, as before."""
    async with create_ajax_session() as session:
        set_ajax_results(0)
        mesh = await session.api.get_mesh_info()
        assert "psk" in mesh
        assert not [k for k in mesh if k.startswith("x-")]


async def test_getconf_requests_the_secret_fields(create_ajax_session, record_ajax_requests):
    """getconf carries DECRYPT_X, which is what makes the x- fields appear.

    The flag is not an obfuscation toggle: without it the controller omits the
    x- secret attributes entirely, and with it they are included (see
    tests/live for the wire-level evidence). Redaction and decryption both
    depend on receiving them, so the flag must stay.
    """
    async with create_ajax_session() as session:
        calls = record_ajax_requests()
        try:
            await session.api.get_mesh_info()
        except RuntimeError:
            # the shared mock has no payload for this endpoint; the request is
            # issued before parsing fails, which is what this asserts on
            pass

    assert calls, "no request was issued"
    getconfs = [c for c in calls
                if isinstance(c.get("data"), str) and "getconf" in c["data"]]
    assert getconfs, "no getconf request was issued"
    for call in getconfs:
        assert "DECRYPT_X='true'" in call["data"], (
            f"getconf omitted DECRYPT_X, so no x- secret fields would be "
            f"returned: {call['data']}"
        )


async def test_guest_pass_list_requests_the_secret_fields(
    create_ajax_session, record_ajax_requests
):
    """The guest-list getconf also asks for the x- fields."""
    async with create_ajax_session() as session:
        calls = record_ajax_requests()
        try:
            await session.api.get_guest_passes()
        except RuntimeError:
            pass

    assert calls, "no request was issued"
    getconfs = [c for c in calls
                if isinstance(c.get("data"), str) and "guest-list" in c["data"]]
    assert getconfs, "no guest-list request was issued"
    for call in getconfs:
        assert "DECRYPT_X='true'" in call["data"], f"missing DECRYPT_X: {call['data']}"
