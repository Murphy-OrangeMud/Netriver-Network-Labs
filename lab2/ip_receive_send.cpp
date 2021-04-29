// #include "sysinclude.h"

#include <iostream>
#include <cstdio>
#include <arpa/inet.h>
#include <cstdlib>

using namespace std;

extern void ip_DiscardPkt(char *pBuffer, int type);
extern void ip_SendtoLower(char *pBuffer, int length);
extern void ip_SendtoUp(char *pBuffer, int length);
extern unsigned int getIpv4Address();

typedef enum {
    STUD_IP_TEST_CHECKSUM_ERROR,
    STUD_IP_TEST_TTL_ERROR,
    STUD_IP_TEST_VERSION_ERROR,
    STUD_IP_TEST_HEADLEN_ERROR,
    STUD_IP_TEST_DESTINATION_ERROR
};

struct ipv4_head {
    unsigned short version_IHL_service;
    unsigned short total_length;
    unsigned short identification;
    unsigned short fragment_offset;
    unsigned short TTL_protocol;
    unsigned short header_checksum;
    unsigned long source_address;
    unsigned long destination_address;
};

typedef unsigned char byte;

int stud_ip_recv(char *pBuffer, unsigned short length) {
    ipv4_head *recv_head = (ipv4_head *)(pBuffer);
    short version = (recv_head->version_IHL_service & 0xf000) >> 12;
    short ttl = (recv_head->TTL_protocol & 0xff00) >> 8;
    short head_len = (recv_head->version_IHL_service & 0x0f00) >> 8;
    unsigned int sum = 0;
    // 按大端顺序加
    sum += ~(recv_head->version_IHL_service);
    sum += ~(recv_head->total_length);
    sum += ~(recv_head->identification);
    sum += ~(recv_head->fragment_offset);
    sum += ~(recv_head->TTL_protocol);
    sum += ~(recv_head->header_checksum);
    sum += ~(recv_head->source_address & 0xffff);
    sum += ~((recv_head->source_address & 0xffff0000) >> 16);
    sum += ~(recv_head->destination_address & 0xffff);
    sum += ~((recv_head->destination_address & 0xffff0000) >> 16);
    sum = ((sum & 0xffff) + ((sum & 0xffff0000) >> 16)) & 0xffff;

    if (version != 4) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_VERSION_ERROR);
        return 1;
    }
    
    if (ntohs(recv_head->total_length) != length) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_HEADLEN_ERROR);
        return 1;
    }

    if (ntohs(ttl) == 0) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_TTL_ERROR);
        return 1;
    }

    if (sum != 0) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_CHECKSUM_ERROR);
        return 1;
    }

    if (ntohl(recv_head->destination_address) != getIpv4Address()) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_DESTINATION_ERROR);
        return 1;
    }

    char *data = pBuffer + head_len;
    ip_SendtoUp(data, length - head_len);

    return 0;
}

int stud_ip_Upsend(char *pBuffer, unsigned short len, unsigned int srcAddr, unsigned int dstAddr, byte protocol, byte ttl) {
    char *send_head = (char *)malloc(len + sizeof(ipv4_head));
    ((ipv4_head *) send_head)->source_address = htonl(srcAddr);
    ((ipv4_head *) send_head)->destination_address = htonl(dstAddr);
    ((ipv4_head *) send_head)->TTL_protocol = (((unsigned short) ttl) << 4) | ((unsigned short) protocol);
    ((ipv4_head *) send_head)->total_length = htons(len + sizeof(ipv4_head));
    ((ipv4_head *) send_head)->identification = (unsigned short) rand();
    ((ipv4_head *) send_head)->fragment_offset = 0x4000;
    ((ipv4_head *) send_head)->version_IHL_service = (0x4000) | ((sizeof(ipv4_head)) << 8);

    unsigned int sum = 0;
    sum += ~(((ipv4_head *) send_head)->version_IHL_service);
    sum += ~(((ipv4_head *) send_head)->total_length);
    sum += ~(((ipv4_head *) send_head)->identification);
    sum += ~(((ipv4_head *) send_head)->fragment_offset);
    sum += ~(((ipv4_head *) send_head)->TTL_protocol);
    sum += ~(((ipv4_head *) send_head)->header_checksum);
    sum += ~(((ipv4_head *) send_head)->source_address & 0xffff);
    sum += ~((((ipv4_head *) send_head)->source_address & 0xffff0000) >> 16);
    sum += ~(((ipv4_head *) send_head)->destination_address & 0xffff);
    sum += ~((((ipv4_head *) send_head)->destination_address & 0xffff0000) >> 16);
    sum = ((sum & 0xffff) + ((sum & 0xffff0000) >> 16)) & 0xffff;
    
    ((ipv4_head *) send_head)->header_checksum = (unsigned short) sum;
    ip_SendtoLower(send_head, len + sizeof(ipv4_head));
    return 0;
}