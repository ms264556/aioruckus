"""Type Hints for SmartZone JSON Payloads"""

from typing import Literal, Required, TypedDict

class SzPermissionResourceItem(TypedDict, total=False):
    resource: str
    access: Literal["NA", "READ", "MODIFY", "FULL_ACCESS"]
    display: str

class SzPermissionCategory(TypedDict, total=False):
    resource: Required[str]
    access: Required[Literal["READ", "MODIFY", "FULL_ACCESS"]]
    display: str
    items: list[SzPermissionResourceItem]
    itemsDescription: list[str]
    ids: list[str]

class SzPermissionExtra(TypedDict, total=False):
    isSuperAdmin: bool
    isSuperAdminOfDomain: bool

class SzPermissionCategories(TypedDict, total=False):
    totalCount: int
    hasMore: bool
    firstIndex: int
    list: Required[list[SzPermissionCategory]]
    extra: SzPermissionExtra

class SzSession(TypedDict, total=False):
    cpId: Required[str]
    domainId: Required[str]
    adminId: Required[str]
    controllerVersion: Required[str]
    permissionCategories: Required[SzPermissionCategories]
    partnerDomain: str
    cpName: str
    cpSerialNumber: str

class NodeStateItem(TypedDict):
    nodeId: str
    nodeName: str
    nodeState: Literal["Out_Of_Service", "In_Service"]

class ManagementServiceStateItem(TypedDict):
    nodeId: str
    nodeName: str
    managementServiceState: Literal["Out_Of_Service", "In_Service"]

class SzClusterState(TypedDict, total=False):
    clusterName: Required[str]
    clusterState: Literal["In_Service", "Out_Of_Service", "Maintenance", "Read_Only", "NetworkPartitionSuspected"]
    clusterRole: Literal["Leader", "Follower"]
    currentNodeId: str
    currentNodeName: str
    nodeStateList: list[NodeStateItem]
    managementServiceStateList: list[ManagementServiceStateItem]