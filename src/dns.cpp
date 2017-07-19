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
    decode_hdr(buffer);
    buffer += hdr_offset;

    decode_qname(buffer);
    m_qType = get16bits(buffer);
    m_qClass = get16bits(buffer);
    //std::cout << "m_qName:" << m_qName << "\n";
    //std::cout << "m_qType:" << m_qType << "\n";
    //std::cout << "m_qClass:" << m_qClass << "\n";

    have_edns = false;
    if (dns_hdr.adcount)
        decode_additional(buffer);
}

void Dns::decode_hdr(const char* buffer)
{
    dns_hdr = *(struct dnshdr*) buffer;

	//dns_hdr.id = EXTRACT_16BITS(&dns_hdr.id);
	dns_hdr.qucount = EXTRACT_16BITS(&dns_hdr.qucount);
	//dns_hdr.ancount = EXTRACT_16BITS(&dns_hdr.ancount);
	//dns_hdr.aucount = EXTRACT_16BITS(&dns_hdr.aucount);
	dns_hdr.adcount = EXTRACT_16BITS(&dns_hdr.adcount);
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

void Dns::decode_additional(const char* buffer)
{
    opt = *(struct optrr*) buffer;
    opt.opt_type = EXTRACT_16BITS(&opt.opt_type);
    opt.opt_udpsize = EXTRACT_16BITS(&opt.opt_udpsize);
    opt.opt_ttl = EXTRACT_32BITS(&opt.opt_ttl);
    opt.rdlen = EXTRACT_16BITS(&opt.rdlen);
    /*std::cout << "name=" << (uint16_t) opt.opt_name
              << ", type=" << opt.opt_type
              << ", class=" << opt.opt_udpsize
              << ", ttl=" << opt.opt_ttl
              << ", rdlen=" << opt.rdlen << "\n";*/
    if (opt.rdlen)
        decode_option(buffer + 11);
}

void Dns::decode_option(const char* p)
{
    eo = *(struct edns0opt*) p;
    if (eo.opt_code == 0x0800) {
        have_edns = true;
        eo.opt_code = EXTRACT_16BITS(&eo.opt_code);
        eo.opt_len = EXTRACT_16BITS(&eo.opt_len);
        eo.family = EXTRACT_16BITS(&eo.family);
        inet_ntop(AF_INET, &eo.sub_addr, client_ip, 16);

        /*std::cout << "opt_code=" << eo.opt_code
                  << ", opt_len=" << eo.opt_len
                  << ", family=" << eo.family
                  << ", smask=" << (uint16_t)eo.source_netmask
                  << ", scropmask=" << (uint16_t)eo.scope_netmask
                  << ", client_ip=" << client_ip << "\n";*/
    } else if (eo.opt_code == 0x0a00) {
        //TODO: COOKIE
    }
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

    /* Code Question section */
    buffer += hdr_offset + query_len;

    /* Code Answer section */
    m_ra.r_zone = 0xc00c;
    m_ra.r_ttl = 0;
    m_ra.r_size = 4;
    uint32_t intip;

    char* p = std::strtok(cstr, ",");
    while (p) {
		put16bits(buffer, m_ra.r_zone);
		put16bits(buffer, m_qType);
		put16bits(buffer, m_qClass);
		put32bits(buffer, m_ra.r_ttl);
		put16bits(buffer, m_ra.r_size);

		intip = inet_addr(p);
		put32bits(buffer, ntohl(intip));

        dns_hdr.ancount++;
        if (dns_hdr.ancount >= 10) break;

        p = std::strtok(NULL, ",");
    }

    /* Code Additional section */
    buffer[0] = opt.opt_name;
    buffer++;
    put16bits(buffer, opt.opt_type);
    opt.opt_udpsize = 512;
    put16bits(buffer, opt.opt_udpsize);
    put32bits(buffer, opt.opt_ttl);

    if (opt.rdlen)
        opt.rdlen = 12;
    put16bits(buffer, opt.rdlen);
    
    if (opt.rdlen) {
        put16bits(buffer, eo.opt_code);
        put16bits(buffer, eo.opt_len);
        put16bits(buffer, eo.family);
        buffer[0] = eo.source_netmask;
        buffer[1] = eo.scope_netmask;
        buffer += 2;
        buffer[0] = (eo.sub_addr & 0xFF);
        buffer[1] = (eo.sub_addr & 0xFF00) >> 8;
        buffer[2] = (eo.sub_addr & 0xFF0000) >> 16;
        buffer[3] = (eo.sub_addr & 0xFF000000) >> 24;
        buffer += 4;
    }

    code_hdr(start_hdr);

    return (buffer - bufferBegin);
}

void Dns::code_hdr(char*& buffer)
{
//	dns_hdr.flags1 = 0x81;
//	dns_hdr.flags2 = 0x80;
	dns_hdr.qucount	= 1;
	//dns_hdr.ancount	= 1;
//	dns_hdr.nscount	= 0;
//	dns_hdr.arcount	= 0;

	buffer += 2;  // skip id
	buffer[0] = 0x81;
	buffer[1] = 0x80;
	buffer += 2;  // skip flags
	put16bits(buffer, dns_hdr.qucount);
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

