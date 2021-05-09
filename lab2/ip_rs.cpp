#include "sysinclude.h"

#include <iostream>
#include <cstdio>
#include <cstring>
// #include <arpa/inet.h>
#include <cstdlib>

using namespace std;

extern void ip_DiscardPkt(char *pBuffer, int type);
extern void ip_SendtoLower(char *pBuffer, int length);
extern void ip_SendtoUp(char *pBuffer, int length);
extern unsigned int getIpv4Address();

/*
typedef enum {
    STUD_IP_TEST_CHECKSUM_ERROR,
    STUD_IP_TEST_TTL_ERROR,
    STUD_IP_TEST_VERSION_ERROR,
    STUD_IP_TEST_HEADLEN_ERROR,
    STUD_IP_TEST_DESTINATION_ERROR
};
*/

// typedef unsigned char byte;

int stud_ip_recv(char *pBuffer, unsigned short length) {
    if (((unsigned int)pBuffer[0]&0xf0) != 0x40) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_VERSION_ERROR);
        return 1;
    }
    if ((((unsigned int)pBuffer[0])&0xf) < 5) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_HEADLEN_ERROR);
        return 1;
    }
    if ((unsigned int)pBuffer[8] == 0) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_TTL_ERROR);
        return 1;
    }
    if (ntohl(((unsigned long *)pBuffer)[4]) != getIpv4Address()) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_DESTINATION_ERROR);
        return 1;
    }
    unsigned int sum = 0;
    for (int i = 0; i < ((unsigned int)pBuffer[0]&0xf)*4; i += 2) {
        sum += (*(unsigned short *)(pBuffer + i));
    }
    unsigned short sum2 = (sum & 0xffff) + (sum >> 16);
    sum2 = ~sum2;
    if (sum2 != 0) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_CHECKSUM_ERROR);
        return 1;
    }

    ip_SendtoUp(pBuffer+((unsigned int)pBuffer[0]&0xf)*4, length);
    return 0;
}

int stud_ip_Upsend(char *pBuffer, unsigned short len, unsigned int srcAddr, unsigned int dstAddr, byte protocol, byte ttl) {
    char buffer[len + 20];
    memset(buffer, 0, sizeof(buffer));

    buffer[0] = 0x45;
    ((unsigned short *)buffer)[1] = htons(len + 20);
    buffer[8] = ttl;
    buffer[9] = protocol;
    ((unsigned long *)buffer)[3] = htonl(srcAddr);
    ((unsigned long *)buffer)[4] = htonl(dstAddr);
    unsigned int sum = 0;
    for (int i = 0; i < 20; i += 2) {
        sum += htons(*(unsigned short *)(buffer + i));
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = ~sum;
    ((unsigned short *)buffer)[5] = htons(sum);
    for (int i = 0; i < len; i++) {
        buffer[i+20] = pBuffer[i];
    }
    ip_SendtoLower(buffer, len+20);
    return 0;
}
