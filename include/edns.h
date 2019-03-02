#ifndef INCLUDE_EDNS_H_
#define INCLUDE_EDNS_H_

#include <cstdint>

#pragma pack(1)

/*
   +------------+--------------+------------------------------+
   | Field Name | Field Type   | Description                  |
   +------------+--------------+------------------------------+
   | NAME       | domain name  | MUST be 0 (root domain)      |
   | TYPE       | u_int16_t    | OPT (41)                     |
   | CLASS      | u_int16_t    | requestor's UDP payload size |
   | TTL        | u_int32_t    | extended RCODE and flags     |
   | RDLEN      | u_int16_t    | length of all RDATA          |
   | RDATA      | octet stream | {attribute,value} pairs      |
   +------------+--------------+------------------------------+
 */
struct optrr {
  uint8_t opt_name;
  uint16_t opt_type;
  uint16_t opt_udpsize;
  uint32_t opt_ttl;
  uint16_t rdlen;
};

/*
    +0 (MSB)                            +1 (LSB)
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 0: |                          OPTION-CODE                          |
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 2: |                         OPTION-LENGTH                         |
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 4: |                            FAMILY                             |
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 6: |          SOURCE NETMASK       |        SCOPE NETMASK          |
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 7: |                           ADDRESS...                          /
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 */
struct edns0opt {
  uint16_t opt_code;
  uint16_t opt_len;
  uint16_t family;
  uint8_t source_netmask;
  uint8_t scope_netmask;
  uint32_t sub_addr;
};

/*
                      client unknow server cookie
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        OPTION-CODE = 10      |       OPTION-LENGTH = 8        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +-+-    Client Cookie (fixed size, 8 bytes)              -+-+-+-+
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


                      client know server cookie
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        OPTION-CODE = 10      |   OPTION-LENGTH >= 16, <= 40   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +-+-    Client Cookie (fixed size, 8 bytes)              -+-+-+-+
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    /       Server Cookie  (variable size, 8 to 32 bytes)           /
    /                                                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct cookieopt {
  uint16_t opt_code;
  uint16_t opt_len;
  char client_cookie[8];
};

#pragma pack()

#endif /* INCLUDE_EDNS_H_ */
