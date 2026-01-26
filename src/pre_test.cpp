/*
  Ido Barnea
  Cisco Systems, Inc.
*/

/*
  Copyright (c) 2016-2017 Cisco Systems, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#include <cstring>
#include <endian.h>
#include <rte_config.h>
#include <rte_ethdev.h>
#include <rte_bus_pci.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <common/Network/Packet/EthernetHeader.h>
#include <common/Network/Packet/Arp.h>
#include "common/Network/Packet/VLANHeader.h"
#include "common/basic_utils.h"
#include "bp_sim.h"
#include "main_dpdk.h"
#include "pkt_gen.h"
#include "pre_test.h"
#include "utils/utl_ipv6_hextets.h"
#include "utl_mbuf.h"
#include "utl_ipv6_hextets.h"

CPretestOnePortInfo::CPretestOnePortInfo() {
    m_state = RESOLVE_NOT_NEEDED;
    m_is_loopback = false;
    m_stats.clear();
}

CPretestOnePortInfo::~CPretestOnePortInfo() {
    for (std::vector<COneIPInfo *>::iterator it = m_src_info.begin(); it != m_src_info.end(); ++it) {
        delete *it;
    }
    for (std::vector<COneIPInfo *>::iterator it = m_dst_info.begin(); it != m_dst_info.end(); ++it) {
        delete *it;
    }
}

void CPretestOnePortInfo::add_src(uint32_t ip, uint16_t vlan, MacAddress mac) {
    COneIPv4Info *already_exist = find_ip(ip, vlan);
    if (already_exist)
        return;

    COneIPv4Info *one_ip = new COneIPv4Info(ip, vlan, mac);
    assert(one_ip);
    m_src_info.push_back(one_ip);
}

void CPretestOnePortInfo::add_dst(uint32_t ip, uint16_t vlan) {
    COneIPv4Info *already_exist = find_next_hop(ip, vlan);
    if (already_exist)
        return;

    MacAddress default_mac;
    COneIPv4Info *one_ip = new COneIPv4Info(ip, vlan, default_mac);
    assert(one_ip);
    m_dst_info.push_back(one_ip);
    m_state = RESOLVE_NEEDED;
}

void CPretestOnePortInfo::add_src(uint16_t ip[8], uint16_t vlan, MacAddress mac) {
    COneIPv6Info *already_exist = find_ipv6(ip, vlan);
    if (already_exist)
        return;

    COneIPv6Info *one_ip = new COneIPv6Info(ip, vlan, mac);
    assert(one_ip);
    m_src_info.push_back(one_ip);
}

void CPretestOnePortInfo::add_dst(uint16_t ip[8], uint16_t vlan) {
    MacAddress default_mac;
    COneIPv6Info *one_ip = new COneIPv6Info(ip, vlan, default_mac);
    assert(one_ip);
    m_dst_info.push_back(one_ip);
    m_state = RESOLVE_NEEDED;
}

void CPretestOnePortInfo::dump(FILE *fd, char *offset) {
    std::string new_offset = std::string(offset) + "  ";

    if (m_is_loopback) {
        fprintf(fd, "%sPort connected in loopback\n", offset);
    }
    fprintf(fd, "%sSources:\n", offset);
    for (std::vector<COneIPInfo *>::iterator it = m_src_info.begin(); it != m_src_info.end(); ++it) {
        (*it)->dump(fd, new_offset.c_str());
    }
    fprintf(fd, "%sDestinations:\n", offset);
    for (std::vector<COneIPInfo *>::iterator it = m_dst_info.begin(); it != m_dst_info.end(); ++it) {
        (*it)->dump(fd, new_offset.c_str());
    }
}

/*
 * Get appropriate source for given vlan and ip version.
 */
COneIPInfo *CPretestOnePortInfo::get_src(uint16_t vlan, uint8_t ip_ver) {
    for (std::vector<COneIPInfo *>::iterator it = m_src_info.begin(); it != m_src_info.end(); ++it) {
        if ((ip_ver == (*it)->ip_ver()) && (vlan == (*it)->get_vlan()))
            return (*it);
    }

    return NULL;
}

COneIPv4Info *CPretestOnePortInfo::find_ip(uint32_t ip, uint16_t vlan) {
    for (std::vector<COneIPInfo *>::iterator it = m_src_info.begin(); it != m_src_info.end(); ++it) {
        if (((*it)->ip_ver() == COneIPInfo::IP4_VER) && ((*it)->get_vlan() == vlan) && (((COneIPv4Info *)(*it))->get_ip() == ip))
            return (COneIPv4Info *) *it;
    }

    return NULL;
}

COneIPv4Info *CPretestOnePortInfo::find_next_hop(uint32_t ip, uint16_t vlan) {

    for (std::vector<COneIPInfo *>::iterator it = m_dst_info.begin(); it != m_dst_info.end(); ++it) {
        if (((*it)->ip_ver() == COneIPInfo::IP4_VER) && ((*it)->get_vlan() == vlan) && (((COneIPv4Info *)(*it))->get_ip() == ip))
            return (COneIPv4Info *) *it;
    }

    return NULL;
}

COneIPv6Info *CPretestOnePortInfo::find_ipv6(uint16_t ip[8], uint16_t vlan) {
    for (std::vector<COneIPInfo *>::iterator it = m_src_info.begin(); it != m_src_info.end(); ++it) {
        if (((*it)->ip_ver() == COneIPInfo::IP6_VER) && ((*it)->get_vlan() == vlan)
            && (! memcmp((uint8_t *) ((COneIPv6Info *) (*it))->get_ipv6(), (uint8_t *)ip, 2*8 /* ???*/ ) ) )
            return (COneIPv6Info *) *it;
    }

    return NULL;
}

COneIPv6Info *CPretestOnePortInfo::find_next_hop_v6(const ipv6_hextets& ip, uint16_t vlan) {
    for (auto* dst : this->m_dst_info) {
        if ((dst->ip_ver() == COneIPInfo::IP6_VER) && (dst->get_vlan() == vlan)
            && !memcmp(((COneIPv6Info *) dst)->get_ipv6(), ip.data(), 2*8))
            return (COneIPv6Info *) dst;
    }
    return NULL;
}

bool CPretestOnePortInfo::get_mac(COneIPInfo *ip, uint8_t *mac) {
    MacAddress defaultmac;

    for (std::vector<COneIPInfo *>::iterator it = m_dst_info.begin(); it != m_dst_info.end(); ++it) {
        if (ip->ip_ver() != (*it)->ip_ver())
            continue;

        switch(ip->ip_ver()) {
        case 4:
            if (*((COneIPv4Info *) (*it)) != *((COneIPv4Info *) ip))
                continue;
            break;
        case 6:
            if (*((COneIPv6Info *) (*it)) != *((COneIPv6Info *) ip))
                continue;
            break;
        default:
            assert(0);
        }

        (*it)->get_mac(mac);
        if (! memcmp(mac, defaultmac.GetConstBuffer(), ETHER_ADDR_LEN)) {
            return false;
        } else {
            return true;
        }
    }

    return false;
}

bool CPretestOnePortInfo::get_mac(uint32_t ip, uint16_t vlan, uint8_t *mac) {
    COneIPv4Info one_ip(ip, vlan);

    return get_mac(&one_ip, mac);
}

bool CPretestOnePortInfo::get_mac(uint16_t ip[8], uint16_t vlan, uint8_t *mac) {
    COneIPv6Info one_ip(ip, vlan);

    return get_mac(&one_ip, mac);
}

// return true if there are still any addresses to resolve on this port
bool CPretestOnePortInfo::resolve_needed() {
    if (m_state == RESOLVE_NOT_NEEDED)
        return false;

    for (std::vector<COneIPInfo *>::iterator it = m_dst_info.begin(); it != m_dst_info.end(); ++it) {
        if ((*it)->resolve_needed())
            return true;
    }

    m_state = RESOLVE_NOT_NEEDED;
    return false;
}

void CPretestOnePortInfo::send_arp_req_all() {
    for (std::vector<COneIPInfo *>::iterator it = m_dst_info.begin(); it != m_dst_info.end(); ++it) {
        int num_sent;
        int verbose = CGlobalInfo::m_options.preview.getVMode();

        if (!(*it)->resolve_needed())
            continue;

        uint32_t pkt_size = (*it)->get_arp_req_len();
        rte_mbuf_t* m = CGlobalInfo::pktmbuf_alloc_by_port(m_port_id, pkt_size);
        if ( unlikely(m == nullptr) )  {
            fprintf(stderr, "ERROR: Could not allocate %u bytes mbuf for sending ARP to port:%d\n", pkt_size, m_port_id);
            exit(1);
        }

        uint8_t *p = (uint8_t *)rte_pktmbuf_append(m, pkt_size);
        if (unlikely(p == nullptr)) {
            fprintf(stderr, "ERROR: Could not append %u bytes to mbuf for sending ARP to port:%d\n", pkt_size, m_port_id);
            exit(1);
        }
        // We need source on the same VLAN of the dest in order to send
        COneIPInfo *sip = get_src((*it)->get_vlan(), (*it)->ip_ver());
        if (sip == NULL) {
            fprintf(stderr, "Failed finding matching source for - ");
            (*it)->dump(stderr);
            exit(1);
        }
        (*it)->fill_arp_req_buf(p, m_port_id, sip);

        if (verbose >= 3) {
            fprintf(stdout, "TX ARP request on port %d - " , m_port_id);
            (*it)->dump(stdout, "");
            if (verbose >= 7) {
                utl_rte_pktmbuf_dump_k12(stdout,m);
            }
        }

        num_sent = m_port->tx_burst(0, &m, 1);
        if (num_sent < 1) {
            fprintf(stderr, "Failed sending ARP to port:%d\n", m_port_id);
            exit(1);
        } else {
            m_stats.m_tx_arp++;
        }
    }
}

void CPretestOnePortInfo::send_grat_arp_all() {
    for (std::vector<COneIPInfo *>::iterator it = m_src_info.begin(); it != m_src_info.end(); ++it) {

        if ((*it)->is_zero_ip())
            continue;

        int num_sent;
        int verbose = CGlobalInfo::m_options.preview.getVMode();

        uint32_t pkt_size = (*it)->get_grat_arp_len();
        rte_mbuf_t* m = CGlobalInfo::pktmbuf_alloc_by_port(m_port_id, pkt_size);
        if ( unlikely(m == nullptr) )  {
            fprintf(stderr, "ERROR: Could not allocate %u bytes mbuf for sending grat ARP on port:%d\n", pkt_size, m_port_id);
            exit(1);
        }

        uint8_t *p = (uint8_t *)rte_pktmbuf_append(m, pkt_size);
        if (unlikely(p == nullptr)) {
            fprintf(stderr, "ERROR: Could not append %u bytes to mbuf for sending grat ARP on port:%d\n", pkt_size, m_port_id);
            exit(1);
        }
        (*it)->fill_grat_arp_buf(p);


        if (verbose >= 3) {
            fprintf(stdout, "TX grat ARP on port %d - " , m_port_id);
            (*it)->dump(stdout, "");
            if (verbose >= 7) {
                utl_rte_pktmbuf_dump_k12(stdout,m);
            }
        }

        num_sent = m_port->tx_burst(0, &m, 1);
        if (num_sent < 1) {
            fprintf(stderr, "Failed sending grat ARP on port:%d\n", m_port_id);
            exit(1);
        } else {
            m_stats.m_tx_arp++;
        }
    }
}

// IPv4 functions
void CPretest::add_ip(uint16_t port, uint32_t ip, uint16_t vlan, MacAddress src_mac) {
    assert(port < m_max_ports);
    m_port_info[port].add_src(ip, vlan, src_mac);
}

void CPretest::add_ip(uint16_t port, uint32_t ip, MacAddress src_mac) {
    assert(port < m_max_ports);
    add_ip(port, ip, 0, src_mac);
}

void CPretest::add_next_hop(uint16_t port, uint32_t ip, uint16_t vlan) {
    assert(port < m_max_ports);
    m_port_info[port].add_dst(ip, vlan);
}

void CPretest::add_next_hop(uint16_t port, uint32_t ip) {
    assert(port < m_max_ports);
    add_next_hop(port, ip, 0);
}

// IPv6 functions
void CPretest::add_ip(uint16_t port, uint16_t ip[8], uint16_t vlan, MacAddress src_mac) {
    assert(port < m_max_ports);
    m_port_info[port].add_src(ip, vlan, src_mac);
}

void CPretest::add_ip(uint16_t port, uint16_t ip[8], MacAddress src_mac) {
    assert(port < m_max_ports);
    add_ip(port, ip, 0, src_mac);
}

void CPretest::add_next_hop(uint16_t port, uint16_t ip[8], uint16_t vlan) {
    assert(port < m_max_ports);
    m_port_info[port].add_dst(ip, vlan);
}

void CPretest::add_next_hop(uint16_t port, uint16_t ip[8]) {
    assert(port < m_max_ports);
    add_next_hop(port, ip, 0);
}

// put in mac, the relevant mac address for the tupple port_id, ip, vlan
bool CPretest::get_mac(uint16_t port_id, uint32_t ip, uint16_t vlan, uint8_t *mac) {
    assert(port_id < m_max_ports);

    return m_port_info[port_id].get_mac(ip, vlan, mac);
}

// IPv6 version of above
bool CPretest::get_mac(uint16_t port_id, uint16_t ip[8], uint16_t vlan, uint8_t *mac) {
    assert(port_id < m_max_ports);

    return m_port_info[port_id].get_mac(ip, vlan, mac);
}

CPreTestStats CPretest::get_stats(uint16_t port_id) {
    assert(port_id < m_max_ports);

    return m_port_info[port_id].get_stats();
}

bool CPretest::is_loopback(uint16_t port) {
    assert(port < m_max_ports);

    return m_port_info[port].is_loopback();
}

bool CPretest::resolve_all() {
    uint16_t port;

    // send ARP request on all ports
    for (port = 0; port < m_max_ports; port++) {
        m_port_info[port].send_arp_req_all();
    }

    int max_tries = 1000;
    int i;
    for (i = 0; i < max_tries; i++) {
        bool all_resolved = true;
        for (port = 0; port < m_max_ports; port++) {
            if (m_port_info[port].resolve_needed()) {
                // We need to stop reading packets only if all ports are resolved.
                // If we are on loopback, We might get requests on port even after it is in RESOLVE_DONE state
                all_resolved = false;
            }
            for (uint16_t queue = 0; queue < m_num_q; queue++) {
                handle_rx(port, queue);
            }
        }
        if (all_resolved) {
            break;
        } else {
            delay(1);
        }
    }

    if (i == max_tries) {
        return false;
    } else {
        return true;
    }

    return true;
}

void CPretest::send_arp_req_all() {
    for (uint16_t port = 0; port < m_max_ports; port++) {
        m_port_info[port].send_arp_req_all();
    }
}

void CPretest::send_grat_arp_all() {
    for (uint16_t port = 0; port < m_max_ports; port++) {
        m_port_info[port].send_grat_arp_all();
    }
}

bool CPretest::is_arp(const uint8_t *p, uint16_t pkt_size, ArpHdr *&arp, uint16_t &vlan_id) {
    EthernetHeader *m_ether = (EthernetHeader *)p;
    vlan_id = 0;
    uint16_t min_size = ETH_HDR_LEN;
    VLANHeader *vlan;

    if (pkt_size < min_size)
        return false;

    switch(m_ether->getNextProtocol()) {
    case EthernetHeader::Protocol::ARP:
        arp = (ArpHdr *)(p + 14);
        min_size += sizeof(ArpHdr);
        break;
    case EthernetHeader::Protocol::VLAN:
        vlan = (VLANHeader *)(p + 14);

        min_size += sizeof(VLANHeader);
        if (pkt_size < min_size)
            return false;

        if (vlan->getNextProtocolHostOrder() != EthernetHeader::Protocol::ARP) {
            return false;
        } else {
            vlan_id = vlan->getTagID();
            arp = (ArpHdr *)(p + 14 + sizeof(VLANHeader));
        }
        min_size += sizeof(ArpHdr);
        break;
    default:
        return false;
    }

    if (pkt_size < min_size)
        return false;
    else
        return true;
}

void CPretest::try_handling_icmpv6(CPretestOnePortInfo* port, const uint8_t *p, uint16_t pkt_size) {
    // No need to process packets other than IPv6
    if (pkt_size < ETH_HDR_LEN + IPV6_HDR_LEN) {
        return;
    }

    auto read_u16_le = [](const uint8_t* data) -> uint16_t {
        // Reverse byte order to return little-endian
        return static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8);
    };

    int verbose = CGlobalInfo::m_options.preview.getVMode();

    ether_header eth_header;
    memcpy(&eth_header, p, sizeof(eth_header));

    // Find L3 header
    uint32_t l3_offset = sizeof(eth_header);
    uint32_t vlan_id = 0;
    for (uint16_t eth_type = be16toh(eth_header.ether_type); eth_type != ETH_P_IPV6;) {
        switch (eth_type) {
            case ETH_P_8021Q:
                vlan_id = read_u16_le(p + l3_offset);
                l3_offset += 4;
                break;
            case ETH_P_8021AD:
                l3_offset += 4;
                break;
            default: {
                if (verbose >= 7) {
                    printf("RX packet with unsupported L3 proto %hu\n", eth_type);
                }
                return;
            }
        }
        eth_type = read_u16_le(p + l3_offset - 2);
    }

    const uint8_t* ipv6_hdr_pos = p + l3_offset;
    ip6_hdr ipv6_header;
    memcpy(&ipv6_header, ipv6_hdr_pos, sizeof(ipv6_header));

    // We care only about ICMPv6 messages
    if (ipv6_header.ip6_nxt != IPPROTO_ICMPV6) {
        if (verbose >= 7) {
            printf("RX IPv6 packet with unsupported L4 proto %d\n", (int)ipv6_header.ip6_nxt);
        }
        return;
    }

    const uint8_t* icmp_hdr_pos = ipv6_hdr_pos + 40;
    icmp6_hdr icmp_header;
    memcpy(&icmp_header, icmp_hdr_pos, sizeof(icmp_header));

    if (icmp_header.icmp6_type == ND_NEIGHBOR_SOLICIT) {
        port->m_stats.m_rx_arp++;

        const uint16_t ipv6_payload_length = be16toh(ipv6_header.ip6_plen);
        if (ipv6_payload_length < sizeof(nd_neighbor_solicit)) {
            if (verbose >= 3) {
                printf("RX NS with invalid payload length %u\n", ipv6_payload_length);
            }
            return;
        }

        nd_neighbor_solicit ns_header;
        memcpy(&ns_header, icmp_hdr_pos, sizeof(ns_header));

        // Check if sender asks for our address
        ipv6_hextets target_ip_le = ipv6_to_le(ns_header.nd_ns_target.s6_addr16);
        auto local_address = port->find_ipv6(target_ip_le.data(), vlan_id);
        if (!local_address) {
            if (verbose >= 7) {
                printf("RX NS for different address: %s\n"
                    , ip_to_str((uint8_t*)target_ip_le.data()).c_str());
            }
            return;
        }

        // We need to reply to this NS
        if (verbose >= 3) {
            printf("RX NS for address: %s\n", ip_to_str((uint8_t*)target_ip_le.data()).c_str());
        }

        auto port_id = port->get_port()->get_repid();
        auto response_size = 92; // Solicited NA
        rte_mbuf* m = CGlobalInfo::pktmbuf_alloc_by_port(port_id, response_size);
        if (unlikely(m == nullptr))  {
            fprintf(stderr
                , "ERROR: Could not allocate %u bytes mbuf for sending NA to port:%d\n"
                , response_size, (int)port_id);
            exit(1);
        }
        auto* response = (uint8_t *)rte_pktmbuf_append(m, response_size);
        if (unlikely(response == nullptr)) {
            fprintf(stderr
                , "ERROR: Could not append %u bytes to mbuf for sending NA to port:%d\n"
                , response_size, (int)port_id);
            exit(1);
        }

        // PktGen expects little-endian
        ipv6_hextets sender_ip_le = ipv6_to_le(ipv6_header.ip6_src.s6_addr16);
        std::array<uint8_t, 6> src_mac;
        local_address->get_mac(src_mac.data());

        // Dst MAC is SRC MAC from request
        uint8_t* dst_mac = eth_header.ether_shost;

        CTestPktGen::create_solicited_neighbor_advertisement(response
            , local_address->get_ipv6()
            , sender_ip_le.data()
            , src_mac.data(), dst_mac, vlan_id);

        int num_sent = port->get_port()->tx_burst(0, &m, 1);
        if (num_sent < 1) {
            fprintf(stderr, "Failed sending NS reply on port:%d\n", (int)port_id);
            rte_pktmbuf_free(m);
        } else {
            if (verbose >= 3) {
                printf("TX solicited NA on port:%d sip:%s, tip:%s\n"
                        , (int)port_id
                        , ip_to_str((uint8_t*)local_address->get_ipv6()).c_str()
                        , ip_to_str((uint8_t*)sender_ip_le.data()).c_str());
            }
            port->m_stats.m_tx_arp++;
        }
    } else if (icmp_header.icmp6_type == ND_NEIGHBOR_ADVERT) {
        port->m_stats.m_rx_arp++;
        const uint16_t ipv6_payload_length = be16toh(ipv6_header.ip6_plen);
        if (ipv6_payload_length < sizeof(nd_neighbor_advert)) {
            if (verbose >= 3) {
                printf("RX NA with invalid payload length %u\n", ipv6_payload_length);
            }
            return;
        }

        nd_neighbor_advert na_header;
        memcpy(&na_header, icmp_hdr_pos, sizeof(na_header));

        ipv6_hextets advertised_ip_le = ipv6_to_le(na_header.nd_na_target.s6_addr16);
        // Check if NA is for one of our gateways
        const char* na_type = (na_header.nd_na_hdr.icmp6_data8[0] & 0x40) ? "solicited" : "unsolicited";
        auto gateway_address = port->find_next_hop_v6(advertised_ip_le, vlan_id);
        if (!gateway_address) {
            if (verbose >= 3) {
                printf("RX %s NA for different address: %s\n", na_type
                    , ip_to_str((uint8_t*)advertised_ip_le.data()).c_str());
            }
            return;
        }

        // This NA is meant for us
        if (verbose >= 3) {
            printf("RX %s NA for local address: %s\n"
                , na_type, ip_to_str((uint8_t*)advertised_ip_le.data()).c_str());
        }

        if (ipv6_payload_length == sizeof(nd_neighbor_advert)) {
            // No ICMPv6 options. Fall back to address from Ethernet header
            uint8_t* advertised_mac = eth_header.ether_shost;
            gateway_address->set_mac(advertised_mac);
            if (verbose >= 3) {
                printf("%s is at %s (NA with no target-link-layer-address option)\n"
                    , ip_to_str((uint8_t*)advertised_ip_le.data()).c_str()
                    , utl_macaddr_to_str(advertised_mac).c_str());
            }
            return;
        }

        // NA should contain target-link-layer-address option
        auto icmp_hdr_option = icmp_hdr_pos + sizeof(nd_neighbor_advert);
        nd_opt_hdr option_header;
        memcpy(&option_header, icmp_hdr_option, sizeof(option_header));
        if (option_header.nd_opt_type != ND_OPT_TARGET_LINKADDR) {
            if (verbose >= 3) {
                printf("%s NA has invalid option type %d\n", na_type, (int)option_header.nd_opt_type);
            }
            return;
        }
        auto* advertised_mac = (uint8_t*)(icmp_hdr_option + 2);
        gateway_address->set_mac(advertised_mac);
        if (verbose >= 3) {
            printf("%s is at %s\n"
                , ip_to_str((uint8_t*)advertised_ip_le.data()).c_str()
                , utl_macaddr_to_str(advertised_mac).c_str());
        }
    } else {
        if (verbose >= 7) {
            printf("RX ICMPv6 packet with unsupported type %d\n", (int)icmp_header.icmp6_type);
        }
    }
}

int CPretest::handle_rx(int port_id, int queue_id) {
    rte_mbuf_t * rx_pkts[32];
    uint16_t cnt;
    int i;
    int verbose = CGlobalInfo::m_options.preview.getVMode();
    int tries = 0;

    do {
        CPretestOnePortInfo *port = &m_port_info[port_id];

        cnt = port->get_port()->rx_burst( queue_id, rx_pkts, sizeof(rx_pkts)/sizeof(rx_pkts[0]));
        tries++;
        bool free_pkt;
        for (i = 0; i < cnt; i++) {
            rte_mbuf_t * m = rx_pkts[i];
            free_pkt = true;
            int pkt_size = rte_pktmbuf_pkt_len(m);
            uint8_t *p = rte_pktmbuf_mtod(m, uint8_t *);
            if (verbose >= 7){
                fprintf(stdout, "RX-gen on port %d queue %d \n",port_id,queue_id);
                utl_rte_pktmbuf_dump_k12(stdout,m);
            }

            ArpHdr *arp;
            uint16_t vlan_id;
            if (is_arp(p, pkt_size, arp, vlan_id)) {
                port->m_stats.m_rx_arp++;
                if (arp->m_arp_op == htons(ArpHdr::ARP_HDR_OP_REQUEST)) {
                    if (verbose >= 3) {
                        bool is_grat = false;
                        if (arp->m_arp_sip == arp->m_arp_tip) {
                            is_grat = true;
                        }
                        fprintf(stdout, "RX %s on port %d queue %d sip:%s tip:%s vlan:%d\n"
                                , is_grat ? "grat ARP" : "ARP request"
                                , port_id, queue_id
                                , ip_to_str(ntohl(arp->m_arp_sip)).c_str()
                                , ip_to_str(ntohl(arp->m_arp_tip)).c_str()
                                , vlan_id);
                        if (verbose >= 7)
                            utl_rte_pktmbuf_dump_k12(stdout,m);
                    }
                    // is this request for our IP?
                    COneIPv4Info *src_addr;
                    COneIPv4Info *rcv_addr;
                    if ((src_addr = port->find_ip(ntohl(arp->m_arp_tip), vlan_id))) {
                        // If our request(i.e. we are connected in loopback)
                        // , do a shortcut, and write info directly to asking port
                        uint8_t magic[5] = {0x1, 0x3, 0x5, 0x7, 0x9};
                        if (! memcmp((uint8_t *)&arp->m_arp_tha.data, magic, 5)) {
                            uint8_t sent_port_id = arp->m_arp_tha.data[5];
                            if ((sent_port_id < m_max_ports) &&
                                (rcv_addr = m_port_info[sent_port_id].find_next_hop(ntohl(arp->m_arp_tip), vlan_id))) {
                                uint8_t mac[ETHER_ADDR_LEN];
                                src_addr->get_mac(mac);
                                rcv_addr->set_mac(mac);
                                port->m_is_loopback = true;
                                m_port_info[sent_port_id].m_is_loopback = true;
                            }
                        } else {
                            // Not our request. Answer.
                            uint8_t src_mac[ETHER_ADDR_LEN];
                            free_pkt = false; // We use the same mbuf to send response. Don't free it twice.
                            arp->m_arp_op = htons(ArpHdr::ARP_HDR_OP_REPLY);
                            uint32_t tmp_ip = arp->m_arp_sip;
                            arp->m_arp_sip = arp->m_arp_tip;
                            arp->m_arp_tip = tmp_ip;
                            memcpy((uint8_t *)&arp->m_arp_tha, (uint8_t *)&arp->m_arp_sha, ETHER_ADDR_LEN);
                            src_addr->get_mac(src_mac);
                            memcpy((uint8_t *)&arp->m_arp_sha, src_mac, ETHER_ADDR_LEN);
                            EthernetHeader *m_ether = (EthernetHeader *)p;
                            memcpy((uint8_t *)&m_ether->myDestination, (uint8_t *)&m_ether->mySource, ETHER_ADDR_LEN);
                            memcpy((uint8_t *)&m_ether->mySource, src_mac, ETHER_ADDR_LEN);
                            int num_sent = port->get_port()->tx_burst(0, &m, 1);
                            if (num_sent < 1) {
                                fprintf(stderr, "Failed sending ARP reply to port:%d\n", port_id);
                                rte_pktmbuf_free(m);
                            } else {
                                if (verbose >= 3) {
                                    fprintf(stdout, "TX ARP reply on port:%d sip:%s, tip:%s\n"
                                            , port_id
                                            , ip_to_str(ntohl(arp->m_arp_sip)).c_str()
                                            , ip_to_str(ntohl(arp->m_arp_tip)).c_str());

                                }
                                port->m_stats.m_tx_arp++;
                            }
                        }
                    } else {
                        // ARP request not to our IP. Check if this is gratuitous ARP for something we need.
                        if ((arp->m_arp_tip == arp->m_arp_sip)
                            && (rcv_addr = port->find_next_hop(ntohl(arp->m_arp_tip), vlan_id))
                            && !CGlobalInfo::m_options.m_garp_ignore) {
                            rcv_addr->set_mac((uint8_t *)&arp->m_arp_sha);
                            fprintf(stdout, "RX grat ARP request for something we need on port:%d sip:%s, tip:%s\n",
                                    port_id,
                                    ip_to_str(ntohl(arp->m_arp_sip)).c_str(), 
                                    ip_to_str(ntohl(arp->m_arp_tip)).c_str());
                        }
                    }
                } else {
                    if (arp->m_arp_op == htons(ArpHdr::ARP_HDR_OP_REPLY)) {
                        if (verbose >= 3) {
                            fprintf(stdout, "RX ARP reply on port %d queue %d sip:%s tip:%s vlan:%d\n"
                                    , port_id, queue_id
                                    , ip_to_str(ntohl(arp->m_arp_sip)).c_str()
                                    , ip_to_str(ntohl(arp->m_arp_tip)).c_str()
                                    , vlan_id);
                        }

                        // If this is response to our request, update our tables
                        COneIPv4Info *addr;
                        if ((addr = port->find_next_hop(ntohl(arp->m_arp_sip), vlan_id))) {
                            addr->set_mac((uint8_t *)&arp->m_arp_sha);
                        }
                    }
                }
            } else {
                try_handling_icmpv6(port, p, pkt_size);
            }
            if (free_pkt)
                rte_pktmbuf_free(m);
        }
    } while ((cnt != 0) && (tries < 1000));

    return 0;
}

void CPretest::get_results(CManyIPInfo &resolved_ips) {
    for (int port = 0; port < m_max_ports; port++) {
        for (std::vector<COneIPInfo *>::iterator it = m_port_info[port].m_dst_info.begin()
                 ; it != m_port_info[port].m_dst_info.end(); ++it) {
            uint8_t ip_type = (*it)->ip_ver();
            (*it)->set_port(port);
            switch(ip_type) {
            case COneIPInfo::IP4_VER:
                resolved_ips.insert(*(COneIPv4Info *)(*it));
                break;
#if 0
                //??? fix for ipv6
            case COneIPInfo::IP6_VER:
                ipv6_tmp = (uint8_t *)((COneIPv6Info *)(*it))->get_ipv6();
                memcpy((uint8_t *)ipv6, (uint8_t *)ipv6_tmp, 16);
                v6_list.insert(std::pair<std::pair<uint16_t[8], uint16_t>, COneIPv6Info>
                               (std::pair<uint16_t[8], uint16_t>(ipv6, vlan), *(COneIPv6Info *)(*it)));
                break;
#endif
            default:
                break;
            }
        }
    }
}

void CPretest::dump(FILE *fd) {
    fprintf(fd, "Pre test info start ===================\n");
    for (int port = 0; port < m_max_ports; port++) {
        fprintf(fd, "Port %d:\n", port);
        m_port_info[port].dump(fd, (char *)"  ");
    }
    fprintf(fd, "Pre test info end ===================\n");
}

void CPretest::test() {
    uint8_t found_mac[ETHER_ADDR_LEN];
    uint8_t mac0[ETHER_ADDR_LEN] = {0x90, 0xe2, 0xba, 0xae, 0x87, 0xd0};
    uint8_t mac1[ETHER_ADDR_LEN] = {0x90, 0xe2, 0xba, 0xae, 0x87, 0xd1};
    uint8_t mac2[ETHER_ADDR_LEN] = {0x90, 0xe2, 0xba, 0xae, 0x87, 0xd2};
    uint32_t ip0  = 0x0f000002;
    uint32_t ip01 = 0x0f000003;
    uint32_t ip1  = 0x0f000001;
    uint16_t ipv6_0[8] = {0x1234, 0x5678, 0xabcd, 0x0, 0x0, 0x0, 0x1111, 0x2220};
    uint16_t ipv6_1[8] = {0x1234, 0x5678, 0xabcd, 0x0, 0x0, 0x0, 0x1111, 0x2221};
    uint16_t vlan=1;
    uint8_t port_0 = 0;
    uint8_t port_1 = 3;

    add_ip(port_0, ip0, vlan, mac0);
    add_ip(port_0, ip01, vlan, mac1);
    add_ip(port_0, ipv6_0, vlan, mac1);
    add_next_hop(port_0, ip1, vlan);
    add_next_hop(port_0, ipv6_1, vlan);

    add_ip(port_1, ip1, vlan, mac2);
    add_ip(port_1, ipv6_1, vlan, mac2);
    add_next_hop(port_1, ip0, vlan);
    add_next_hop(port_1, ip01, vlan);
    add_next_hop(port_1, ipv6_0, vlan);

    dump(stdout);
    send_grat_arp_all();
    resolve_all();
    dump(stdout);

    if (!get_mac(port_0, ip1, vlan, found_mac)) {
        fprintf(stderr, "Test failed: Could not find %x on port %d\n", ip1, port_0);
        exit(1);
    }
    if (memcmp(found_mac, mac2, ETHER_ADDR_LEN)) {
        fprintf(stderr, "Test failed: dest %x on port %d badly resolved\n", ip1, port_0);
        exit(1);
    }

    if (!get_mac(port_1, ip0, vlan, found_mac)) {
        fprintf(stderr, "Test failed: Could not find %x on port %d\n", ip0, port_1);
        exit(1);
    }
    if (memcmp(found_mac, mac0, ETHER_ADDR_LEN)) {
        fprintf(stderr, "Test failed: dest %x on port %d badly resolved\n", ip0, port_1);
        exit(1);
    }

    printf("Test passed\n");
    exit(0);
}
