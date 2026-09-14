"""Live tests for the DECRYPT_X flag and how the controller exposes secrets.

``DECRYPT_X`` is not an obfuscation toggle. It is a *field-selection* flag:
without it the controller omits its ``x-`` secret attributes from a getconf
response, and with it they are included. Both the ciphertext form and a bare
equivalent are then present, carrying the same value.

This matters because decryption and redaction in ``parse_ajax_response`` can
only act on values that were returned in the first place, so dropping the flag
would silently stop the library seeing any secrets at all.

These tests are read-only. They are marked ``live`` and deselected by default;
see the module docstring in ``test_live_stats.py`` for the env vars.
"""

import os
import re
from contextlib import asynccontextmanager

import pytest

from aioruckus.ajaxsession import AjaxSession

pytestmark = pytest.mark.live


def _unleashed():
    host = os.environ.get("AIORUCKUS_LIVE_UNLEASHED_HOST")
    user = os.environ.get("AIORUCKUS_LIVE_UNLEASHED_USERNAME")
    password = os.environ.get("AIORUCKUS_LIVE_UNLEASHED_PASSWORD")
    return host, user, password


@asynccontextmanager
async def _raw_session():
    """A live session plus its underlying transport, for raw payload access."""
    host, user, password = _unleashed()
    if not (host and user and password):
        pytest.skip("Unleashed credentials not configured "
                    "(set AIORUCKUS_LIVE_UNLEASHED_* env vars)")
    async with AjaxSession.async_create(host, user, password) as session:
        # the inner UnleashedSession, which owns _ajax_request
        transport = session._api._RuckusAjaxApi__session
        yield session.api, transport


async def _getconf(transport, comp: str, decrypt_x: bool) -> str:
    flag = " DECRYPT_X='true'" if decrypt_x else ""
    return await transport._ajax_request(
        "_conf.jsp",
        f"<ajax-request action='getconf'{flag} updater='{comp}.1.2' comp='{comp}'/>",
    )


@pytest.mark.asyncio
async def test_decrypt_x_controls_whether_x_fields_are_returned():
    """Without the flag the x- secret fields are absent; with it they appear."""
    async with _raw_session() as (_api, transport):
        for comp in ("ap-list", "wlansvc-list", "system"):
            without = await _getconf(transport, comp, decrypt_x=False)
            with_flag = await _getconf(transport, comp, decrypt_x=True)

            xs_without = set(re.findall(r"\b(x-[\w-]+)=", without))
            xs_with = set(re.findall(r"\b(x-[\w-]+)=", with_flag))

            assert not xs_without, (
                f"{comp}: expected no x- fields without DECRYPT_X, "
                f"got {sorted(xs_without)}"
            )
            assert xs_with, (
                f"{comp}: expected x- fields with DECRYPT_X, got none — the "
                f"controller may have changed how it exposes secrets"
            )


@pytest.mark.asyncio
async def test_decrypt_x_false_returns_a_shorter_response():
    """The flag adds fields rather than transforming the existing ones."""
    async with _raw_session() as (_api, transport):
        without = await _getconf(transport, "system", decrypt_x=False)
        with_flag = await _getconf(transport, "system", decrypt_x=True)
        # Not an equality check on size, since values vary; the flag only adds.
        assert len(with_flag) > len(without)


@pytest.mark.asyncio
async def test_dual_secret_fields_carry_the_same_value():
    """An AP's psk appears both as ``x-psk`` and ``psk``, with one value.

    A caller that echoes a parsed payload back into a setter therefore sends
    both spellings; the controller accepts that and stores one value.
    """
    async with _raw_session() as (_api, transport):
        text = await _getconf(transport, "ap-list", decrypt_x=True)
        assert "x-psk=" in text, "no x-psk returned; cannot compare the pair"
        x_vals = re.findall(r'\bx-psk="([^"]*)"', text)
        bare_vals = re.findall(r'(?<!x-)\bpsk="([^"]*)"', text)
        assert x_vals, "x-psk not found"
        assert bare_vals, "bare psk not found alongside x-psk"
        # Whichever pairing the controller uses, every value in the pair must
        # agree, otherwise a round-trip would be ambiguous.
        assert set(x_vals) == set(bare_vals)
