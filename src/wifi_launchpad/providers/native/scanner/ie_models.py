"""Data models for parsed 802.11 information elements."""

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class SecurityInfo:
    """Parsed security information from RSN/WPA IEs"""
    version: int = 0
    group_cipher: str = ""
    pairwise_ciphers: List[str] = None
    akm_suites: List[str] = None  # Authentication Key Management
    rsn_capabilities: int = 0
    pmkid_count: int = 0
    pmkids: List[bytes] = None
    group_management_cipher: str = ""

    # Parsed capabilities
    pre_auth: bool = False
    no_pairwise: bool = False
    ptksa_replay_counter: int = 0
    gtksa_replay_counter: int = 0
    mfp_required: bool = False
    mfp_capable: bool = False
    joint_multi_band_rsna: bool = False
    peerkey_enabled: bool = False
    spp_amsdu_capable: bool = False
    spp_amsdu_required: bool = False
    pbac: bool = False
    extended_key_id: bool = False

    def __post_init__(self):
        if self.pairwise_ciphers is None:
            self.pairwise_ciphers = []
        if self.akm_suites is None:
            self.akm_suites = []
        if self.pmkids is None:
            self.pmkids = []


@dataclass
class HTCapabilities:
    """802.11n HT Capabilities"""
    ldpc_coding: bool = False
    channel_width_40: bool = False
    sm_power_save: str = ""
    greenfield: bool = False
    short_gi_20: bool = False
    short_gi_40: bool = False
    tx_stbc: bool = False
    rx_stbc: int = 0
    delayed_block_ack: bool = False
    max_amsdu_length: int = 0
    dsss_cck_40: bool = False
    psmp: bool = False
    forty_mhz_intolerant: bool = False
    lsig_txop_protection: bool = False

    # AMPDU parameters
    ampdu_max_length: int = 0
    ampdu_min_spacing: float = 0

    # Supported MCS rates
    mcs_rates: List[int] = None

    # Extended capabilities
    pco: bool = False
    pco_transition_time: int = 0
    mcs_feedback: str = ""
    htc_support: bool = False
    rd_responder: bool = False

    def __post_init__(self):
        if self.mcs_rates is None:
            self.mcs_rates = []


@dataclass
class VHTCapabilities:
    """802.11ac VHT Capabilities"""
    max_mpdu_length: int = 0
    supported_channel_widths: List[str] = None
    rx_ldpc: bool = False
    short_gi_80: bool = False
    short_gi_160: bool = False
    tx_stbc: bool = False
    rx_stbc: int = 0
    su_beamformer: bool = False
    su_beamformee: bool = False
    beamformee_sts_capability: int = 0
    sounding_dimensions: int = 0
    mu_beamformer: bool = False
    mu_beamformee: bool = False
    vht_txop_ps: bool = False
    htc_vht: bool = False
    max_ampdu_length: int = 0
    link_adaptation: str = ""
    rx_antenna_pattern: bool = False
    tx_antenna_pattern: bool = False

    # MCS support
    rx_mcs_map: Dict[int, int] = None  # NSS -> max MCS
    tx_mcs_map: Dict[int, int] = None
    rx_highest_rate: int = 0
    tx_highest_rate: int = 0

    def __post_init__(self):
        if self.supported_channel_widths is None:
            self.supported_channel_widths = []
        if self.rx_mcs_map is None:
            self.rx_mcs_map = {}
        if self.tx_mcs_map is None:
            self.tx_mcs_map = {}


@dataclass
class ExtendedCapabilities:
    """Extended Capabilities IE"""
    bss_coexistence_mgmt: bool = False
    extended_channel_switching: bool = False
    wave_indication: bool = False
    psmp_capability: bool = False
    s_psmp_support: bool = False
    event: bool = False
    diagnostics: bool = False
    multicast_diagnostics: bool = False
    location_tracking: bool = False
    fms: bool = False
    proxy_arp: bool = False
    collocated_interference_reporting: bool = False
    civic_location: bool = False
    geospatial_location: bool = False
    tfs: bool = False
    wnm_sleep_mode: bool = False
    tim_broadcast: bool = False
    bss_transition: bool = False  # 802.11r
    qos_traffic_capability: bool = False
    ac_station_count: bool = False
    multiple_bssid: bool = False
    timing_measurement: bool = False
    channel_usage: bool = False
    ssid_list: bool = False
    dms: bool = False
    utc_tsf_offset: bool = False
    tdls_peer_uapsd_buffer_sta: bool = False
    tdls_peer_psm: bool = False
    tdls_channel_switching: bool = False
    interworking: bool = False
    qos_map: bool = False
    ebr: bool = False
    sspn_interface: bool = False
    msgcf_capability: bool = False
    tdls_support: bool = False
    tdls_prohibited: bool = False
    tdls_channel_switching_prohibited: bool = False
    reject_unadmitted_frame: bool = False
    service_interval_granularity: int = 0
    identifier_location: bool = False
    uapsd_coexistence: bool = False
    wnm_notification: bool = False
    qab_capability: bool = False
    utf8_ssid: bool = False
    qmf_activated: bool = False
    qmf_reconfiguration_activated: bool = False
    robust_av_streaming: bool = False
    advanced_gcr: bool = False
    mesh_gcr: bool = False
    scs: bool = False
    qload_report: bool = False
    alternate_edca: bool = False
    unprotected_txop_negotiation: bool = False
    protected_txop_negotiation: bool = False
    protected_qload_report: bool = False
    tdls_wider_bandwidth: bool = False
    operating_mode_notification: bool = False
    max_number_of_msdus_in_amsdu: int = 0
    channel_schedule_management: bool = False
    geodatabase_inband_enabling_signal: bool = False
    network_channel_control: bool = False
    white_space_map: bool = False
    channel_availability_query: bool = False
    fine_timing_measurement_responder: bool = False
    fine_timing_measurement_initiator: bool = False
    fils_capability: bool = False
    extended_spectrum_management: bool = False
    future_channel_guidance: bool = False
    pav: bool = False
    ndp_ps: bool = False
    tpu: bool = False
    wnm_dms_support: bool = False
    link_adaptation_support: bool = False



__all__ = ["ExtendedCapabilities", "HTCapabilities", "SecurityInfo", "VHTCapabilities"]
