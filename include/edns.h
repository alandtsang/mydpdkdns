#ifndef INCLUDE_EDNS_H_
#define INCLUDE_EDNS_H_

#include <cstdint>

#pragma pack(1)

struct optrr {
    uint8_t  opt_name;
    uint16_t opt_type;
    uint16_t opt_class;
    uint32_t opt_ttl;
    uint16_t rdlen;
};

struct edns0opt {
    uint16_t opt_code;
    uint16_t opt_len;
    uint16_t family;
    uint8_t  source_netmask;
    uint8_t  scope_netmask;
    uint32_t sub_addr;
};


#endif /*INCLUDE_EDNS_H_ */
