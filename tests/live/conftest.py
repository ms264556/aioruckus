"""Live-test configuration.

Shadow the autouse ``aiohttp_context`` mock from ``tests/conftest.py``: live
tests must reach the real controller over the network, not the mock router.
"""

import pytest


@pytest.fixture(autouse=True)
def aiohttp_context():
    """No-op: live tests hit the real controller instead of the mock."""
    yield
