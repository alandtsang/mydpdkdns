#include <string>
#include <iostream>
#include <cstring>
#include <vector>
#include <utility>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dns.h"

/*
 * Decode
 */
void Dns::decode(const char* buffer)
{
    //decode_hdr(buffer);
    buffer += hdr_offset;

    decode_qname(buffer);
    m_qType = get16bits(buffer);
    m_qClass = get16bits(buffer);
    //std::cout << "m_qName:" << m_qName << "\n";
    //std::cout << "m_qType:" << m_qType << "\n";
    //std::cout << "m_qClass:" << m_qClass << "\n";
}

void Dns::decode_hdr(const char* buffer)
{
	EXTRACT_16BITS(&dns_hdr.id);
	EXTRACT_16BITS(&dns_hdr.qdcount);
	EXTRACT_16BITS(&dns_hdr.ancount);
	EXTRACT_16BITS(&dns_hdr.nscount);
	EXTRACT_16BITS(&dns_hdr.arcount);
}

void Dns::decode_qname(const char*& buffer)
{
    m_qName.clear();

    int length = *buffer++;
    while (length != 0) {
        for (int i = 0; i < length; i++) {
            char c = *buffer++;
            m_qName.append(1, c);
        }
        length = *buffer++;
        if (length != 0) m_qName.append(1,'.');
    }

    query_len = m_qName.length() + 2 + 4;
}

/*
 * Code
 */
int Dns::code(char* buffer)
{
    char* bufferBegin = buffer;
    char* start_hdr = buffer;

    char cstr[256] = {0};
    std::strcpy(cstr, domain_ip_.c_str());
    dns_hdr.ancount = 0;

    //code_hdr(buffer);
    //buffer += hdr_offset;

    // Code Question section
    buffer += hdr_offset + query_len;

    // Code Answer section
    char* p = std::strtok(cstr, ",");
    while (p) {
		m_ra.r_zone = 0xc00c;
		m_ra.r_ttl = 0;
		m_ra.r_size = 4;

		put16bits(buffer, m_ra.r_zone);
		put16bits(buffer, m_qType);
		put16bits(buffer, m_qClass);
		put32bits(buffer, m_ra.r_ttl);
		put16bits(buffer, m_ra.r_size);
		uint32_t intip = inet_addr(p);
		put32bits(buffer, ntohl(intip));

        dns_hdr.ancount++;
        if (dns_hdr.ancount >= 10) break;

        p = std::strtok(NULL, ",");
    }

    code_hdr(start_hdr);

    return (buffer - bufferBegin);
}

void Dns::code_hdr(char*& buffer)
{
//	dns_hdr.flags1 = 0x81;
//	dns_hdr.flags2 = 0x80;
	dns_hdr.qdcount	= 1;
	//dns_hdr.ancount	= 1;
//	dns_hdr.nscount	= 0;
//	dns_hdr.arcount	= 0;

	buffer += 2;  // skip id
	buffer[0] = 0x81;
	buffer[1] = 0x80;
	buffer += 2;  // skip flags
	put16bits(buffer, dns_hdr.qdcount);
	put16bits(buffer, dns_hdr.ancount);
	//buffer += 4;  // skip auth and add
}

void Dns::code_domain(char*& buffer, const std::string& domain)
{
    int start(0); // indexes
    std::size_t end;

    while ((end = domain.find('.', start)) != std::string::npos) {
        *buffer++ = end - start; // label length octet
        for (int i=start; i<end; i++) {
            *buffer++ = domain[i]; // label octets
        }
        start = end + 1; // Skip '.'
    }

    *buffer++ = domain.size() - start; // last label length octet
    for (int i=start; i<domain.size(); i++) {
        *buffer++ = domain[i]; // last label octets
    }

    *buffer++ = 0;
}

