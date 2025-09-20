"""Type Hints for Ruckus One JSON Payloads"""

from typing import Required, TypedDict, Literal

class AccessControlPolicyDict(TypedDict, total=False):
    name: Required[str]
    macAddresses: Required[list[str]]
    id: Required[str]
    access: Literal["ALLOW", "BLOCK"]
    description: str
    wifiNetworkIds: list[str]

class AccessControlProfileDict(TypedDict, total=False):
    id: Required[str]
    name: Required[str]
    l2AclPolicyId: str
    l2AclPolicy: AccessControlPolicyDict
    wifiNetworkIds: list[str]

