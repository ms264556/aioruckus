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

class GuestUserDict(TypedDict, total=False):
    """A Ruckus One guest user (guest pass) payload."""
    id: str
    name: str
    password: str
    ssid: str
    networkId: str
    email: str
    mobilePhoneNumber: str
    notes: str
    disabled: bool
    maxDevices: int
    deliveryMethods: list[str]
    expiration: dict
    createdDate: int
    expirationDate: int
    lastModified: int
    guestUserType: str
    macAddresses: list[str]

