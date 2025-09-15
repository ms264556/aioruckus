from typing import Required, TypedDict, Optional, Literal

class R1BssColoring(TypedDict, total=False):
    bssColoringEnabled: bool
    useVenueSettings: bool

class R1ClientAdmissionControl(TypedDict, total=False):
    enable24G: bool
    enable50G: bool
    maxRadioLoad24G: int
    maxRadioLoad50G: int
    minClientCount24G: int
    minClientCount50G: int
    minClientThroughput24G: int
    minClientThroughput50G: int
    useVenueSettings: bool

class R1DeviceGps(TypedDict, total=False):
    latitude: str
    longitude: str

class R1NetworkSettings(TypedDict, total=False):
    gateway: str
    ip: str
    ipType: Literal["DYNAMIC", "STATIC"]
    netmask: str
    primaryDnsServer: str
    secondaryDnsServer: str


class R1Position(TypedDict, total=False):
    floorplanId: str
    xPercent: float
    yPercent: float


class R1ApRadioParams(TypedDict, total=False):
    allowedChannels: list[str]
    changeInterval: int
    channelBandwidth: str
    manualChannel: int
    method: Literal["MANUAL", "AUTO"]
    operativeChannel: int
    operativeTxPower: str
    snr_dB: int
    txPower: str
    useVenueSettings: bool


class R1ApRadioParams6G(TypedDict, total=False):
    allowedChannels: list[str]
    bssMinRate6G: str
    changeInterval: int
    channelBandwidth: str
    channelBandwidth320MhzGroup: str
    enableMulticastDownlinkRateLimiting: bool
    enableMulticastUplinkRateLimiting: bool
    manualChannel: int
    method: Literal["MANUAL", "AUTO"]
    mgmtTxRate6G: str
    multicastDownlinkRateLimiting: int
    multicastUplinkRateLimiting: int
    operativeChannel: int
    operativeTxPower: str
    snr_dB: int
    txPower: str
    useVenueSettings: bool


class R1ApRadioParamsDual5G(TypedDict, total=False):
    enabled: bool
    lower5gEnabled: bool
    radioParamsLower5G: R1ApRadioParams
    radioParamsUpper5G: R1ApRadioParams
    upper5gEnabled: bool
    useVenueEnabled: bool


class R1Radio(TypedDict, total=False):
    apRadioParams24G: R1ApRadioParams
    apRadioParams50G: R1ApRadioParams
    apRadioParams6G: R1ApRadioParams6G
    apRadioParamsDual5G: R1ApRadioParamsDual5G
    enable24G: bool
    enable50G: bool
    enable6G: bool
    useVenueSettings: bool


class R1Ap(TypedDict, total=False):
    apGroupId: str
    bssColoring: R1BssColoring
    clientAdmissionControl: R1ClientAdmissionControl
    clientCount: int
    description: str
    deviceGps: R1DeviceGps
    externalIp: str
    firmware:Required[str]
    indoorModel: bool
    ip: str
    lastContacted: str
    lastUpdated: str
    mac: Required[str]
    meshRole: str
    model: Required[str]
    name: Required[str]
    networkSettings: R1NetworkSettings
    poePortStatus: str
    position: R1Position
    radio: R1Radio
    serialNumber: Required[str]
    state: str
    subState: str
    tags: list[str]
    uptime_seconds: int
    venueId: Required[str]

class R1AccessControlPolicy(TypedDict, total=False):
    name: Required[str]
    macAddresses: Required[list[str]]
    id: Required[str]
    access: Literal["ALLOW", "BLOCK"]
    description: str
    wifiNetworkIds: list[str]

class R1AccessControlProfile(TypedDict, total=False):
    id: Required[str]
    name: Required[str]
    l2AclPolicyId: str
    l2AclPolicy: R1AccessControlPolicy
    wifiNetworkIds: list[str]

