"""Type Hints for SmartZone JSON Payloads"""

from typing import Literal, Required, TypedDict

from .ajaxtyping import L2Rule

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
    apiVersion: Required[str]
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

class SzBlockClientZone(TypedDict, total=False):
    id: Required[str]
    zoneId: Required[str]
    description: str
    modifiedDateTime: int
    modifierUsername: str

class SzBlockClient(L2Rule, total=False):
    zones: Required[list[SzBlockClientZone]]

class SzCellularGpsHistoryItem(TypedDict, total=False):
    timestamp: Required[int]
    latitude: Required[str]
    longitude: Required[str]

class SzIndoorMapXy(TypedDict):
    x: Required[float]
    y: Required[float]

class SzApOperational(TypedDict):
    registrationTime: int
    indoorMapId: str
    channel24G: str
    channel24gValue: int
    configOverride: bool
    deviceName: Required[str]
    enabledBonjourGateway: bool
    numClients24G: int
    dataBladeName: str
    retry24G: int
    airtime24G: int
    noise5G: int
    model: Required[str]
    numClients: int
    capacity24G: int
    firmwareVersion: Required[str]
    provisionMethod: str
    latency24G: int
    retry5G: int
    ip: str
    apMac: Required[str]
    noise24G: int
    lastSeen: int
    configurationStatus: str
    airtime5G: int
    alerts: int
    lbsStatus: str
    status: str
    numClients5G: int
    ipv6Address: str
    capacity50G: int
    wlanGroup24Name: str
    connectionFailure: float
    description: str
    capacity: int
    meshRole: str
    channel5G: str
    channel50gValue: int
    managementVlan: int
    wlanGroup50Name: str
    wlanGroup24Id: str
    controlBladeName: str
    zoneName: str
    tx: int
    rx: int
    txRx: int
    tx24G: int
    tx50G: int
    rx24G: int
    rx50G: int
    txRx24G: int
    txRx50G: int
    meshMode: str
    extPort: str
    administrativeState: str
    apGroupName: str
    latency50G: int
    indoorMapXy: SzIndoorMapXy
    apGroupId: Required[str]
    extIp: str
    airtime: int
    provisionStage: str
    indoorMapName: str
    indoorMapLocation: str
    deviceGps: str
    serial: Required[str]
    location: str
    wlanGroup50Id: str
    registrationState: str
    zoneId: Required[str]
    zoneFirmwareVersion: str
    zoneAffinityProfileName: str
    connectionStatus: str
    domainId: Required[str]
    domainName: str
    dpIp: str
    controlBladeId: str
    isCriticalAp: bool
    crashDump: int
    cableModemSupported: bool
    cableModemResetSupported: bool
    swapInMac: str
    swapOutMac: str
    packetCaptureState: str
    isOverallHealthStatusFlagged: bool
    isLatency24GFlagged: bool
    isCapacity24GFlagged: bool
    isConnectionFailure24GFlagged: bool
    isLatency50GFlagged: bool
    isCapacity50GFlagged: bool
    isConnectionFailure50GFlagged: bool
    isConnectionTotalCountFlagged: bool
    isConnectionFailureFlagged: bool
    isAirtimeUtilization24GFlagged: bool
    isAirtimeUtilization50GFlagged: bool
    eirp24G: int
    eirp50G: int
    supportFips: bool
    fipsEnabled: bool
    uptime: int
    ipsecSessionTime: int
    ipsecTxPkts: int
    ipsecRxPkts: int
    ipsecTxBytes: int
    ipsecRxBytes: int
    ipsecTxDropPkts: int
    ipsecRxDropPkts: int
    ipsecTxIdleTime: int
    ipsecRxIdleTime: int
    ipType: str
    ipv6Type: str
    cellularWanInterface: str
    cellularConnectionStatus: str
    cellularSignalStrength: str
    cellularIMSISIM0: str
    cellularIMSISIM1: str
    cellularICCIDSIM0: str
    cellularICCIDSIM1: str
    cellularIsSIM0Present: str
    cellularIsSIM1Present: str
    cellularTxBytesSIM0: int
    cellularTxBytesSIM1: int
    cellularRxBytesSIM0: int
    cellularRxBytesSIM1: int
    cellularActiveSim: str
    cellularIPaddress: str
    cellularSubnetMask: str
    cellularDefaultGateway: str
    cellularOperator: str
    cellular3G4GChannel: int
    cellularCountry: str
    cellularRadioUptime: int
    cellularGpsHistory: list[SzCellularGpsHistoryItem]
    medianTxRadioMCSRate24G: int
    medianTxRadioMCSRate50G: int
    medianRxRadioMCSRate24G: int
    medianRxRadioMCSRate50G: int
    monitoringEnabled: bool
    txPowerOffset24G: int
    txPowerOffset5G: int
    rxDesense24G: int
    rxDesense5G: int
    cumulativeTx24G: int
    cumulativeRx24G: int
    cumulativeTxRx24G: int
    cumulativeTx5G: int
    cumulativeRx5G: int
    cumulativeTxRx5G: int