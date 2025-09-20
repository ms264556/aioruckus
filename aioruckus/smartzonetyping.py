"""Type Hints for SmartZone JSON Payloads"""

from typing import Literal, Required, TypedDict

from .ajaxtyping import L2Rule

class PermissionResourceItemDict(TypedDict, total=False):
    resource: str
    access: Literal["NA", "READ", "MODIFY", "FULL_ACCESS"]
    display: str

class PermissionCategoryDict(TypedDict, total=False):
    resource: Required[str]
    access: Required[Literal["READ", "MODIFY", "FULL_ACCESS"]]
    display: str
    items: list[PermissionResourceItemDict]
    itemsDescription: list[str]
    ids: list[str]

class PermissionExtraDict(TypedDict, total=False):
    isSuperAdmin: bool
    isSuperAdminOfDomain: bool

class PermissionCategoriesDict(TypedDict, total=False):
    totalCount: int
    hasMore: bool
    firstIndex: int
    list: Required[list[PermissionCategoryDict]]
    extra: PermissionExtraDict

class SessionDict(TypedDict, total=False):
    cpId: Required[str]
    domainId: Required[str]
    adminId: Required[str]
    apiVersion: Required[str]
    controllerVersion: Required[str]
    permissionCategories: Required[PermissionCategoriesDict]
    partnerDomain: str
    cpName: str
    cpSerialNumber: str

class BlockClientZoneDict(TypedDict, total=False):
    id: Required[str]
    zoneId: Required[str]
    description: str
    modifiedDateTime: int
    modifierUsername: str

class BlockClientDict(L2Rule, total=False):
    zones: Required[list[BlockClientZoneDict]]
