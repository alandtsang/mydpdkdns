#ifndef INCLUDE_DNS_H_
#define	INCLUDE_DNS_H_

#include <string>
#include <sys/types.h>
#include <arpa/inet.h>

#include "edns.h"


static inline uint16_t
EXTRACT_16BITS(const void *p)
{
	return ((uint16_t)ntohs(*(const uint16_t *)(p)));
}

static inline uint32_t
EXTRACT_32BITS(const void *p)
{
    return ((uint32_t)ntohl(*(const uint32_t *)(p)));
}


/*
 * Define constants based on rfc883
 */
#define PACKETSZ	512		/* maximum packet size */
#define MAXDNAME	256		/* maximum domain name */
#define MAXCDNAME	255		/* maximum compressed domain name */
#define MAXLABEL	63		/* maximum length of domain label */
	/* Number of bytes of fixed size data in query structure */
#define QFIXEDSZ	4
	/* number of bytes of fixed size data in resource record */
#define RRFIXEDSZ	10

/*
 * Currently defined opcodes
 */
#define QUERY		0x0		/* standard query */
#define IQUERY		0x1		/* inverse query */
#define STATUS		0x2		/* nameserver status query */
#if 0
#define xxx		0x3		/* 0x3 reserved */
#endif
	/* non standard - supports ALLOW_UPDATES stuff from Mike Schwartz */
#define UPDATEA		0x9		/* add resource record */
#define UPDATED		0xa		/* delete a specific resource record */
#define UPDATEDA	0xb		/* delete all named resource record */
#define UPDATEM		0xc		/* modify a specific resource record */
#define UPDATEMA	0xd		/* modify all named resource record */

#define ZONEINIT	0xe		/* initial zone transfer */
#define ZONEREF		0xf		/* incremental zone referesh */

/*
 * Undefine various #defines from various System V-flavored OSes (Solaris,
 * SINIX, HP-UX) so the compiler doesn't whine that we redefine them.
 */
#ifdef T_NULL
#undef T_NULL
#endif
#ifdef T_OPT
#undef T_OPT
#endif
#ifdef T_UNSPEC
#undef T_UNSPEC
#endif
#ifdef NOERROR
#undef NOERROR
#endif

/*
 * Currently defined response codes
 */
#define NOERROR		0		/* no error */
#define FORMERR		1		/* format error */
#define SERVFAIL	2		/* server failure */
#define NXDOMAIN	3		/* non existent domain */
#define NOTIMP		4		/* not implemented */
#define REFUSED		5		/* query refused */
	/* non standard */
#define NOCHANGE	0xf		/* update failed to change db */

/*
 * Type values for resources and queries
 */
#define T_A		1		/* host address */
#define T_NS		2		/* authoritative server */
#define T_MD		3		/* mail destination */
#define T_MF		4		/* mail forwarder */
#define T_CNAME		5		/* connonical name */
#define T_SOA		6		/* start of authority zone */
#define T_MB		7		/* mailbox domain name */
#define T_MG		8		/* mail group member */
#define T_MR		9		/* mail rename name */
#define T_NULL		10		/* null resource record */
#define T_WKS		11		/* well known service */
#define T_PTR		12		/* domain name pointer */
#define T_HINFO		13		/* host information */
#define T_MINFO		14		/* mailbox information */
#define T_MX		15		/* mail routing information */
#define T_TXT		16		/* text strings */
#define	T_RP		17		/* responsible person */
#define	T_AFSDB		18		/* AFS cell database */
#define T_X25		19		/* X_25 calling address */
#define T_ISDN		20		/* ISDN calling address */
#define T_RT		21		/* router */
#define	T_NSAP		22		/* NSAP address */
#define	T_NSAP_PTR	23		/* reverse lookup for NSAP */
#define T_SIG		24		/* security signature */
#define T_KEY		25		/* security key */
#define T_PX		26		/* X.400 mail mapping */
#define T_GPOS		27		/* geographical position (withdrawn) */
#define T_AAAA		28		/* IP6 Address */
#define T_LOC		29		/* Location Information */
#define T_NXT		30		/* Next Valid Name in Zone */
#define T_EID		31		/* Endpoint identifier */
#define T_NIMLOC	32		/* Nimrod locator */
#define T_SRV		33		/* Server selection */
#define T_ATMA		34		/* ATM Address */
#define T_NAPTR		35		/* Naming Authority PoinTeR */
#define T_KX		36		/* Key Exchanger */
#define T_CERT		37		/* Certificates in the DNS */
#define T_A6		38		/* IP6 address */
#define T_DNAME		39		/* non-terminal redirection */
#define T_SINK		40		/* unknown */
#define T_OPT		41		/* EDNS0 option (meta-RR) */
#define T_APL		42		/* lists of address prefixes */
#define T_DS		43		/* Delegation Signer */
#define T_SSHFP		44		/* SSH Fingerprint */
#define T_IPSECKEY	45		/* IPsec keying material */
#define T_RRSIG		46		/* new security signature */
#define T_NSEC		47		/* provable insecure information */
#define T_DNSKEY	48		/* new security key */
	/* non standard */
#define T_SPF		99		/* sender policy framework */
#define T_UINFO		100		/* user (finger) information */
#define T_UID		101		/* user ID */
#define T_GID		102		/* group ID */
#define T_UNSPEC	103		/* Unspecified format (binary data) */
#define T_UNSPECA	104		/* "unspecified ascii". Ugly MIT hack */
	/* Query type values which do not appear in resource records */
#define T_TKEY		249		/* Transaction Key [RFC2930] */
#define T_TSIG		250		/* Transaction Signature [RFC2845] */
#define T_IXFR		251		/* incremental transfer [RFC1995] */
#define T_AXFR		252		/* transfer zone of authority */
#define T_MAILB		253		/* transfer mailbox records */
#define T_MAILA		254		/* transfer mail agent records */
#define T_ANY		255		/* wildcard match */

/*
 * Values for class field
 */

#define C_IN		1		/* the arpa internet */
#define C_CHAOS		3		/* for chaos net (MIT) */
#define C_HS		4		/* for Hesiod name server (MIT) (XXX) */
	/* Query class values which do not appear in resource records */
#define C_ANY		255		/* wildcard match */
#define C_QU		0x8000		/* mDNS QU flag in queries */
#define C_CACHE_FLUSH	0x8000		/* mDNS cache flush flag in replies */

/*
 * Status return codes for T_UNSPEC conversion routines
 */
#define CONV_SUCCESS 0
#define CONV_OVERFLOW -1
#define CONV_BADFMT -2
#define CONV_BADCKSUM -3
#define CONV_BADBUFLEN -4

#pragma pack(1)

/*
 * Structure for query header.
 */
struct dnshdr {
	uint16_t id;		/* query identification number */
	uint8_t  flags1;	/* first byte of flags */
	uint8_t  flags2;	/* second byte of flags */
	uint16_t qucount;	/* number of question entries */
	uint16_t ancount;	/* number of answer entries */
	uint16_t aucount;	/* number of authority entries */
	uint16_t adcount;	/* number of additional entries */
};

/*
 * Macros for subfields of flag fields.
 */
#define DNS_QR(np)	((np)->flags1 & 0x80)		/* response flag */
#define DNS_OPCODE(np)	((((np)->flags1) >> 3) & 0xF)	/* purpose of message */
#define DNS_AA(np)	((np)->flags1 & 0x04)		/* authoritative answer */
#define DNS_TC(np)	((np)->flags1 & 0x02)		/* truncated message */
#define DNS_RD(np)	((np)->flags1 & 0x01)		/* recursion desired */

#define DNS_RA(np)	((np)->flags2 & 0x80)	/* recursion available */
#define DNS_AD(np)	((np)->flags2 & 0x20)	/* authentic data from named */
#define DNS_CD(np)	((np)->flags2 & 0x10)	/* checking disabled by resolver */
#define DNS_RCODE(np)	((np)->flags2 & 0xF)	/* response code */

/*
 * Defines for handling compressed domain names, EDNS0 labels, etc.
 */
#define INDIR_MASK	0xc0	/* 11.... */
#define EDNS0_MASK	0x40	/* 01.... */
#  define EDNS0_ELT_BITLABEL 0x01

/*
 * Structure for passing resource records around.
 */
struct respanswer {
	int16_t		r_zone;		/* zone number */
	int16_t		r_type;		/* type number */
	int16_t		r_class;	/* class number */
	uint32_t	r_ttl;		/* time to live */
	int16_t		r_size;		/* size of data area */
	std::string	r_data;		/* pointer to data */
};

#pragma pack()

const uint8_t hdr_offset = 12;


class Dns {
public:
	Dns() {
        m_qName.reserve(128);
        domain_ip_.reserve(256);
    }
	~Dns() {}

	inline std::string& get_domain_name() { return m_qName; }
	inline void set_answer(uint16_t ancount) { dns_hdr.ancount = ancount; }

	inline void set_domain_ip_group(std::string& domain_ip) {
        domain_ip_ = domain_ip;
    }

	void decode(const char* buffer);
	int code(char* buffer);

    /* edns */
    bool have_edns;
    char client_ip[16];
    struct edns0opt eo;

private:
	void decode_hdr(const char* buffer);
	void decode_qname(const char*& buffer);
    void decode_additional(const char* buffer);
    void decode_option(const char* buffer);

	void code_hdr(char*& buffer);
	void code_domain(char*& buffer, const std::string& domain);


	inline int get16bits(const char*& buffer) {
	    int value = static_cast<unsigned char> (buffer[0]);
	    value = value << 8;
	    value += static_cast<unsigned char> (buffer[1]);
	    buffer += 2;

	    return value;
	}

	inline void put16bits(char*& buffer, uint16_t value) {
	    buffer[0] = (value & 0xFF00) >> 8;
	    buffer[1] = value & 0xFF;
	    buffer += 2;
	}

	inline void put32bits(char*& buffer, uint32_t value) {
	    buffer[0] = (value & 0xFF000000) >> 24;
	    buffer[1] = (value & 0xFF0000) >> 16;
	    buffer[2] = (value & 0xFF00) >> 8;
	    buffer[3] = (value & 0xFF);
	    buffer += 4;
	}

	struct dnshdr dns_hdr;
	std::string	m_qName;
	uint16_t	m_qType;
	uint16_t	m_qClass;

    struct optrr opt;
	struct respanswer m_ra;

    uint16_t query_len;

    std::string domain_ip_;
    size_t domain_ip_len_;
    char cstr[512];
    struct in_addr addr;

    Dns(const Dns&);
    void operator=(const Dns&);
};

#endif /* _DNS_H_ */
