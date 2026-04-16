"""Capability-related IE parsing mixins."""

import struct

from .ie_models import ExtendedCapabilities, HTCapabilities, VHTCapabilities


class CapabilityParsingMixin:
    def _parse_ht_capabilities(self, data: bytes) -> HTCapabilities:
        """Parse HT (802.11n) Capabilities"""
        if len(data) < 26:
            return None

        ht = HTCapabilities()

        # HT Capability Info (2 bytes)
        cap_info = struct.unpack('<H', data[0:2])[0]
        ht.ldpc_coding = bool(cap_info & 0x0001)
        ht.channel_width_40 = bool(cap_info & 0x0002)
        sm_power_save = (cap_info >> 2) & 0x3
        ht.sm_power_save = ["Static", "Dynamic", "Reserved", "Disabled"][sm_power_save]
        ht.greenfield = bool(cap_info & 0x0010)
        ht.short_gi_20 = bool(cap_info & 0x0020)
        ht.short_gi_40 = bool(cap_info & 0x0040)
        ht.tx_stbc = bool(cap_info & 0x0080)
        ht.rx_stbc = (cap_info >> 8) & 0x3
        ht.delayed_block_ack = bool(cap_info & 0x0400)
        ht.max_amsdu_length = 7935 if (cap_info & 0x0800) else 3839
        ht.dsss_cck_40 = bool(cap_info & 0x1000)
        ht.psmp = bool(cap_info & 0x2000)
        ht.forty_mhz_intolerant = bool(cap_info & 0x4000)
        ht.lsig_txop_protection = bool(cap_info & 0x8000)

        # AMPDU Parameters (1 byte)
        ampdu_params = data[2]
        ht.ampdu_max_length = (1 << (13 + (ampdu_params & 0x3))) - 1
        min_spacing = (ampdu_params >> 2) & 0x7
        spacing_values = [0, 0.25, 0.5, 1, 2, 4, 8, 16]
        ht.ampdu_min_spacing = spacing_values[min_spacing] if min_spacing < len(spacing_values) else 0

        # Supported MCS Set (16 bytes)
        mcs_set = data[3:19]
        # Extract supported MCS rates (simplified - just check which are set)
        for i in range(77):  # MCS 0-76
            byte_idx = i // 8
            bit_idx = i % 8
            if byte_idx < len(mcs_set) and (mcs_set[byte_idx] & (1 << bit_idx)):
                ht.mcs_rates.append(i)

        # HT Extended Capabilities (2 bytes)
        if len(data) >= 21:
            ext_cap = struct.unpack('<H', data[19:21])[0]
            ht.pco = bool(ext_cap & 0x0001)
            ht.pco_transition_time = ["400us", "1.5ms", "5ms", "Reserved"][(ext_cap >> 1) & 0x3]
            mcs_feedback = (ext_cap >> 8) & 0x3
            ht.mcs_feedback = ["No feedback", "Reserved", "Unsolicited", "Both"][mcs_feedback]
            ht.htc_support = bool(ext_cap & 0x0400)
            ht.rd_responder = bool(ext_cap & 0x0800)

        return ht

    def _parse_vht_capabilities(self, data: bytes) -> VHTCapabilities:
        """Parse VHT (802.11ac) Capabilities"""
        if len(data) < 12:
            return None

        vht = VHTCapabilities()

        # VHT Capability Info (4 bytes)
        cap_info = struct.unpack('<I', data[0:4])[0]

        max_mpdu = cap_info & 0x3
        vht.max_mpdu_length = [3895, 7991, 11454, -1][max_mpdu]

        supported_widths = (cap_info >> 2) & 0x3
        if supported_widths == 0:
            vht.supported_channel_widths = ["80MHz"]
        elif supported_widths == 1:
            vht.supported_channel_widths = ["80MHz", "160MHz"]
        elif supported_widths == 2:
            vht.supported_channel_widths = ["80MHz", "80+80MHz", "160MHz"]

        vht.rx_ldpc = bool(cap_info & 0x0010)
        vht.short_gi_80 = bool(cap_info & 0x0020)
        vht.short_gi_160 = bool(cap_info & 0x0040)
        vht.tx_stbc = bool(cap_info & 0x0080)
        vht.rx_stbc = (cap_info >> 8) & 0x7
        vht.su_beamformer = bool(cap_info & 0x0800)
        vht.su_beamformee = bool(cap_info & 0x1000)
        vht.beamformee_sts_capability = ((cap_info >> 13) & 0x7) + 1
        vht.sounding_dimensions = ((cap_info >> 16) & 0x7) + 1
        vht.mu_beamformer = bool(cap_info & 0x080000)
        vht.mu_beamformee = bool(cap_info & 0x100000)
        vht.vht_txop_ps = bool(cap_info & 0x200000)
        vht.htc_vht = bool(cap_info & 0x400000)

        max_ampdu = (cap_info >> 23) & 0x7
        vht.max_ampdu_length = (1 << (13 + max_ampdu)) - 1

        link_adapt = (cap_info >> 26) & 0x3
        vht.link_adaptation = ["No feedback", "Reserved", "Unsolicited", "Both"][link_adapt]

        vht.rx_antenna_pattern = bool(cap_info & 0x10000000)
        vht.tx_antenna_pattern = bool(cap_info & 0x20000000)

        # VHT MCS Set (8 bytes)
        if len(data) >= 12:
            # RX MCS Map (2 bytes)
            rx_mcs = struct.unpack('<H', data[4:6])[0]
            # TX MCS Map (2 bytes)
            tx_mcs = struct.unpack('<H', data[6:8])[0]

            # Parse MCS support for each spatial stream (1-8)
            for nss in range(1, 9):
                rx_val = (rx_mcs >> ((nss - 1) * 2)) & 0x3
                tx_val = (tx_mcs >> ((nss - 1) * 2)) & 0x3

                # 0 = MCS 0-7, 1 = MCS 0-8, 2 = MCS 0-9, 3 = Not supported
                if rx_val < 3:
                    vht.rx_mcs_map[nss] = 7 + rx_val
                if tx_val < 3:
                    vht.tx_mcs_map[nss] = 7 + tx_val

            # RX/TX highest supported rate
            vht.rx_highest_rate = struct.unpack('<H', data[8:10])[0] & 0x1FFF
            vht.tx_highest_rate = struct.unpack('<H', data[10:12])[0] & 0x1FFF

        return vht

    def _parse_extended_capabilities(self, data: bytes) -> ExtendedCapabilities:
        """Parse Extended Capabilities IE"""
        ext = ExtendedCapabilities()

        # Extended capabilities can vary in length
        # Parse known capability bits

        if len(data) > 0:
            byte0 = data[0]
            ext.bss_coexistence_mgmt = bool(byte0 & 0x01)
            ext.extended_channel_switching = bool(byte0 & 0x04)
            ext.wave_indication = bool(byte0 & 0x08)
            ext.psmp_capability = bool(byte0 & 0x10)
            ext.s_psmp_support = bool(byte0 & 0x40)

        if len(data) > 1:
            byte1 = data[1]
            ext.event = bool(byte1 & 0x01)
            ext.diagnostics = bool(byte1 & 0x02)
            ext.multicast_diagnostics = bool(byte1 & 0x04)
            ext.location_tracking = bool(byte1 & 0x08)
            ext.fms = bool(byte1 & 0x10)
            ext.proxy_arp = bool(byte1 & 0x20)
            ext.collocated_interference_reporting = bool(byte1 & 0x40)
            ext.civic_location = bool(byte1 & 0x80)

        if len(data) > 2:
            byte2 = data[2]
            ext.geospatial_location = bool(byte2 & 0x01)
            ext.tfs = bool(byte2 & 0x02)
            ext.wnm_sleep_mode = bool(byte2 & 0x04)
            ext.tim_broadcast = bool(byte2 & 0x08)
            ext.bss_transition = bool(byte2 & 0x10)  # 802.11r
            ext.qos_traffic_capability = bool(byte2 & 0x20)
            ext.ac_station_count = bool(byte2 & 0x40)
            ext.multiple_bssid = bool(byte2 & 0x80)

        if len(data) > 3:
            byte3 = data[3]
            ext.timing_measurement = bool(byte3 & 0x01)
            ext.channel_usage = bool(byte3 & 0x02)
            ext.ssid_list = bool(byte3 & 0x04)
            ext.dms = bool(byte3 & 0x08)
            ext.utc_tsf_offset = bool(byte3 & 0x10)
            ext.tdls_peer_uapsd_buffer_sta = bool(byte3 & 0x20)
            ext.tdls_peer_psm = bool(byte3 & 0x40)
            ext.tdls_channel_switching = bool(byte3 & 0x80)

        if len(data) > 4:
            byte4 = data[4]
            ext.interworking = bool(byte4 & 0x01)
            ext.qos_map = bool(byte4 & 0x02)
            ext.ebr = bool(byte4 & 0x04)
            ext.sspn_interface = bool(byte4 & 0x08)
            ext.msgcf_capability = bool(byte4 & 0x20)
            ext.tdls_support = bool(byte4 & 0x40)
            ext.tdls_prohibited = bool(byte4 & 0x80)

        if len(data) > 5:
            byte5 = data[5]
            ext.tdls_channel_switching_prohibited = bool(byte5 & 0x01)
            ext.reject_unadmitted_frame = bool(byte5 & 0x02)
            ext.service_interval_granularity = (byte5 >> 2) & 0x7
            ext.identifier_location = bool(byte5 & 0x20)
            ext.uapsd_coexistence = bool(byte5 & 0x40)
            ext.wnm_notification = bool(byte5 & 0x80)

        if len(data) > 6:
            byte6 = data[6]
            ext.qab_capability = bool(byte6 & 0x01)
            ext.utf8_ssid = bool(byte6 & 0x02)
            ext.qmf_activated = bool(byte6 & 0x04)
            ext.qmf_reconfiguration_activated = bool(byte6 & 0x08)
            ext.robust_av_streaming = bool(byte6 & 0x10)
            ext.advanced_gcr = bool(byte6 & 0x20)
            ext.mesh_gcr = bool(byte6 & 0x40)
            ext.scs = bool(byte6 & 0x80)

        if len(data) > 7:
            byte7 = data[7]
            ext.qload_report = bool(byte7 & 0x01)
            ext.alternate_edca = bool(byte7 & 0x02)
            ext.unprotected_txop_negotiation = bool(byte7 & 0x04)
            ext.protected_txop_negotiation = bool(byte7 & 0x08)
            ext.protected_qload_report = bool(byte7 & 0x20)
            ext.tdls_wider_bandwidth = bool(byte7 & 0x40)
            ext.operating_mode_notification = bool(byte7 & 0x80)

        if len(data) > 8:
            byte8 = data[8]
            ext.max_number_of_msdus_in_amsdu = 1 if (byte8 & 0x01) else 0
            ext.channel_schedule_management = bool(byte8 & 0x02)
            ext.geodatabase_inband_enabling_signal = bool(byte8 & 0x04)
            ext.network_channel_control = bool(byte8 & 0x08)
            ext.white_space_map = bool(byte8 & 0x10)
            ext.channel_availability_query = bool(byte8 & 0x20)
            ext.fine_timing_measurement_responder = bool(byte8 & 0x40)
            ext.fine_timing_measurement_initiator = bool(byte8 & 0x80)

        return ext


__all__ = ["CapabilityParsingMixin"]
