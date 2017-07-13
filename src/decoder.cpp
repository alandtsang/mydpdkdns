#include <unordered_map>

#include <rte_ether.h>

#include "decoder.h"

#define IP_DEFTTL  64   /* from RFC 1340. */                                                                                                                                                                                                
#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)
#define RTE_CPU_TO_BE_16(cpu_16_v) \
    (uint16_t) ((((cpu_16_v) & 0xFF) << 8) | ((cpu_16_v) >> 8))

extern uint32_t local_ip;


uint16_t
Decoder::ip_sum(const unaligned_uint16_t *hdr, int hdr_len)
{
    uint32_t sum = 0;

    while (hdr_len > 1) {
        sum += *hdr++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        hdr_len -= 2;
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

void Decoder::swap_addr(struct ether_addr *src, struct ether_addr *dst) {
    struct ether_addr temp;
    temp = *src;
    *src = *dst;
    *dst = temp;
}

void Decoder::swap_ipaddr(uint32_t *src, uint32_t *dst) {
    *src ^= *dst;
    *dst ^= *src;
    *src ^= *dst;
}

void Decoder::swap_port(uint16_t *src, uint16_t *dst) {
    *src ^= *dst;
    *dst ^= *src;
    *src ^= *dst;
}

unsigned
Decoder::process_pkts(struct rte_mbuf *m)
{
    struct ether_hdr* ehdr;
    uint8_t mac_dst_addr[ETHER_ADDR_LEN];
    uint8_t mac_src_addr[ETHER_ADDR_LEN];

    struct ipv4_hdr *ip_hdr;
    uint32_t ip_dst, ip_src;

    struct udp_hdr *udp_hdr;
    uint16_t port_src, port_dst;

    struct dnshdr *dns_hdr;

    unsigned txpkts = 0;

    ehdr = rte_pktmbuf_mtod(m, struct ether_hdr*);

    /* If not ip packet, forward to kni */
    if (ehdr->ether_type != rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
        return txpkts;
    }

//  rte_memcpy(mac_dst_addr, ehdr->d_addr.addr_bytes, ETHER_ADDR_LEN);
//  rte_memcpy(mac_src_addr, ehdr->s_addr.addr_bytes, ETHER_ADDR_LEN);

    ip_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, sizeof(struct ether_hdr));
    if (ip_hdr->dst_addr != local_ip)
        return txpkts;

    ip_dst = rte_be_to_cpu_32(ip_hdr->dst_addr);
    ip_src = rte_be_to_cpu_32(ip_hdr->src_addr);

    switch (ip_hdr->next_proto_id) {
        case IPPROTO_UDP:
        {
            udp_hdr = (struct udp_hdr *)((unsigned char *)ip_hdr + sizeof(struct ipv4_hdr));
            port_dst = rte_be_to_cpu_16(udp_hdr->dst_port);
            port_src = rte_be_to_cpu_16(udp_hdr->src_port);

            if (port_dst != 53) {
                return txpkts;
            }

            memcpy(&addr, &ip_hdr->src_addr, 4);
            ip = inet_ntoa(addr);  // user src ip

            char* buff = (char *)udp_hdr +  sizeof(struct udp_hdr);
            char* buffstart = buff;

            dns.decode(buff);

            /* Get domain group */
            qName = dns.get_domain_name();

            domain_ip = "153.37.234.35";  // for test
            dns.set_domain_ip_group(domain_ip);

            if (logger->enabled)
                logger->log_info("[info] qtype=A " "domain=%s "
                        "answer=%s " "src_ip=%s ",
                        qName.c_str(), domain_ip.c_str(), ip);

            struct rte_mbuf  *pkt;
            struct ether_hdr *eth_hdr = ehdr;

            pkt = m;
            pkt->next = NULL;

            /* Ethernet */
//          eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
//          rte_memcpy(&eth_hdr->d_addr, mac_src_addr, ETHER_ADDR_LEN);
//          rte_memcpy(&eth_hdr->s_addr, mac_dst_addr, ETHER_ADDR_LEN);
//          eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
            swap_addr(&eth_hdr->s_addr, &eth_hdr->d_addr);

            /* IP */
            //ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
            memset(ip_hdr, 0, sizeof(*ip_hdr));
            ip_hdr->version_ihl     = IP_VHL_DEF;
            ip_hdr->type_of_service = 0;
            ip_hdr->fragment_offset = 0;
            ip_hdr->time_to_live    = IP_DEFTTL;
            ip_hdr->next_proto_id   = IPPROTO_UDP;
            ip_hdr->packet_id       = 0;
            ip_hdr->src_addr        = rte_cpu_to_be_32(ip_dst);
            ip_hdr->dst_addr        = rte_cpu_to_be_32(ip_src);
            //swap_ipaddr(&ip_hdr->src_addr, &ip_hdr->dst_addr);

            /* UDP */
            //udp_hdr = (struct udp_hdr *)(ip_hdr + 1);
            //udp_hdr->src_port     = rte_cpu_to_be_16(port_dst);
            //udp_hdr->dst_port     = rte_cpu_to_be_16(port_src);
            swap_port(&udp_hdr->src_port, &udp_hdr->dst_port);
            udp_hdr->dgram_cksum    = 0; /* No UDP checksum. */

            /* DNS */
            //int dnslen = dns.code(buffstart);
            int dnslen = dns.code(buffstart);

            pkt->nb_segs        = 1;
            //pkt->pkt_len      = 14+20+8+12+pbuf - bufferBegin;
            pkt->pkt_len        = 14+20+8+dnslen;
            pkt->data_len       = pkt->pkt_len;
            ip_hdr->total_length = RTE_CPU_TO_BE_16(pkt->pkt_len - sizeof(*eth_hdr));
            ip_hdr->hdr_checksum = ip_sum((unaligned_uint16_t *)ip_hdr, sizeof(*ip_hdr));
            udp_hdr->dgram_len  = RTE_CPU_TO_BE_16(pkt->pkt_len - sizeof(*eth_hdr) - sizeof(*ip_hdr));
            //pkt->ol_flags     = ol_flags;
            //pkt->vlan_tci     = vlan_tci;
            //pkt->vlan_tci_outer   = vlan_tci_outer;
            pkt->l2_len         = sizeof(struct ether_hdr);
            pkt->l3_len         = sizeof(struct ipv4_hdr);

            total_dns_pkts++;
            return 1;
        }

        default:
        {
            return txpkts;
        }
    }
}

