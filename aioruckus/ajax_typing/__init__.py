"""Type Hints for AJAX AP Payloads"""

import sys

from .stats import Level1, Level2, Level3
from .ap import ap
from .client import client

if sys.version_info >= (3, 11):
    from typing import TypeVar
else:
    from typing_extensions import TypeVar

__all__ = [
    "ap",
    "client",
    "Level1",
    "Level2",
    "Level3",
]
