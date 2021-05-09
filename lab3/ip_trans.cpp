# define LOCAL

#include <iostream>
#include <cstdio>
#ifdef LOCAL
#include <arpa/inet.h>
#endif
#include <vector>
#include <map>
#ifndef LOCAL
#include "sysinclude.h"
#endif
using namespace std;

extern void fwd_SendtoLower(char *pBuffer, int length, unsigned int nexthop);
extern void fwd_LocalRcv(char *pBuffer, int length);
extern void fwd_DiscardPkt(char *pBuffer, int type);
extern unsigned int getIpv4Address();

#ifdef LOCAL
enum {
    STUD_FORWARD_TEST_TTLERROR,
    STUD_FORWARD_TEST_NOROUTE
};

typedef unsigned char byte;

struct stud_route_msg {
    unsigned int dest;
    unsigned int masklen;
    unsigned int nexthop;
};
#endif

vector<stud_route_msg*> route_map;

void stud_Route_Init() {
}

void stud_route_add(stud_route_msg *proute) {
    stud_route_msg *to_add = new stud_route_msg();
    to_add->dest = proute->dest;
    to_add->masklen = proute->masklen;
    to_add->nexthop = proute->nexthop;

    route_map.push_back(to_add);
}

int count_prefix_zero_bit(unsigned int num) {
    int cnt = 0;
    unsigned int mask = (1 << 31);
    while (mask) {
        if (mask & num == 0) {
            cnt++;
            mask >>= 1;
        } else {
            return cnt;
        }
    }
    return 32;
}

stud_route_msg *route_find(unsigned int dest) {
    int maxlen = 0, maxidx = -1;
    for (int i = 0; i < route_map.size(); i++) {
        if (count_prefix_zero_bit(ntohl(dest) ^ ntohl(route_map[i]->dest)) >= route_map[i]->masklen) {
            if (route_map[i]->masklen >= maxlen) {
                maxlen = route_map[i]->masklen;
                maxidx = i;
            }
        }
    }
    if (maxidx == -1) {
        return NULL;
    }
    return route_map[maxidx];
}

int stud_fwd_deal(char *pBuffer, int length) {
    unsigned int dest_addr = ((unsigned long *)pBuffer)[4];
    printf("dest_addr: %x\n", dest_addr);
    if (ntohl(dest_addr) == getIpv4Address()) { //
        fwd_LocalRcv(pBuffer, length);
        return 0;
    }
    stud_route_msg *message = route_find(dest_addr);
    if (message == NULL) {
        fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_NOROUTE);
        return 1;
    }
    if ((unsigned int)pBuffer[8]== 0) {
        fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_TTLERROR);
        return 1;
    }
    pBuffer[8] -= 1;
    unsigned int sum = 0;
    for (int i = 0; i < ((unsigned int)pBuffer[0]&0xf)*4; i += 2) {
        if (i == 10) continue; //
        sum += (*(unsigned short *)(pBuffer + i));
    }
    unsigned short sum2 = (sum & 0xffff) + (sum >> 16);
    sum2 = ~sum2;
    ((unsigned short *)pBuffer)[5] = (sum2);
    if (dest_addr == getIpv4Address()) {
        fwd_LocalRcv(pBuffer, length);
    } else {
        fwd_SendtoLower(pBuffer, length, message->nexthop);
    }
    return 0;
}
