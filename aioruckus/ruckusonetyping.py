"""Type Hints for Ruckus One JSON Payloads"""

import sys

if sys.version_info >= (3, 11):
    from typing import Literal, Required, TypedDict
else:
    from typing_extensions import Literal, Required, TypedDict

class AccessControlPolicyDict(TypedDict, total=False):
    """An L2 ACL policy payload from the Ruckus One API."""
    name: Required[str]
    macAddresses: Required[list[str]]
    id: Required[str]
    access: Literal["ALLOW", "BLOCK"]
    description: str
    wifiNetworkIds: list[str]

class AccessControlProfileDict(TypedDict, total=False):
    """An access control profile payload from the Ruckus One API."""
    id: Required[str]
    name: Required[str]
    l2AclPolicyId: str
    l2AclPolicy: AccessControlPolicyDict
    wifiNetworkIds: list[str]

