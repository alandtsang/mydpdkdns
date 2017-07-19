#ifndef INCLUDE_DECODER_H_
#define INCLUDE_DECODER_H_

#include <memory>

#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include "dns.h"
#include "decoder.h"
#include "logger.h"


class Decoder {
public:
    Decoder() {
        logger = dnslog::Logger::getLogger();
    }
    ~Decoder() {}
    unsigned process_pkts(struct rte_mbuf* m);

    Dns dns;

    std::shared_ptr<dnslog::Logger> logger;

    uint64_t total_dns_pkts;
    uint64_t total_enqueue;

private:
    inline uint16_t ip_sum(const unaligned_uint16_t *hdr, int hdr_len);
    inline void swap_addr(struct ether_addr *src, struct ether_addr *dst);
    inline void swap_ipaddr(uint32_t *src, uint32_t *dst);
    inline void swap_port(uint16_t *src, uint16_t *dst);

    /* proto */
    struct ether_hdr* ehdr;
    struct ipv4_hdr* ip_hdr;
    struct udp_hdr* udp_hdr;
    struct dnshdr* dns_hdr;

    //uint8_t mac_dst_addr[ETHER_ADDR_LEN];
    //uint8_t mac_src_addr[ETHER_ADDR_LEN];
    uint32_t ip_dst, ip_src;
    uint16_t port_src, port_dst;


    /* dns info */
    std::string qName;

    /* user ip info */
    struct in_addr addr;
    char ip[16];
    char* sub_addr;
    std::string domain_ip;
};


#endif
