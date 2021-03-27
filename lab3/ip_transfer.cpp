#include <iostream>
#include <cstdio>
#include <arpa/inet.h>
#include <random>
#include <vector>
#include <map>
// #include "sysinclude.h"
using namespace std;

extern void fwd_SendtoLower(char *pBuffer, int length, unsigned int nexthop);
extern void fwd_LocalRcv(char *pBuffer, int length);
extern void fwd_DiscardPkt(char *pBuffer, int type);
extern unsigned int getIpv4Address();

enum {
    STUD_FORWARD_TEST_TTLERROR,
    STUD_FORWARD_TEST_NOROUTE
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

struct stud_route_msg {
    unsigned int dest;
    unsigned int masklen;
    unsigned int nexthop;
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

struct route_list_node {
    int depth; // 0->ip_1->1->ip_2->2->ip_3->3->ip_4->4(leaf)
    map<unsigned char, route_list_node*> sons;
    stud_route_msg *message; // 只有叶节点才有
    route_list_node(int d = 0): depth(d) {}
};

route_list_node *root;

void stud_Route_Init() {
    root = new route_list_node();
}

void stud_route_add(stud_route_msg *proute) {
    route_list_node *current = root;
    unsigned int ip = proute->dest;
    for (int i = 0; i < 4; i++) {
        unsigned char seg = ((ip >> ((3 - i) * 8)) & 0xff);
        if (current->sons.find(seg) == current->sons.end()) {
            current->sons[seg] = new route_list_node(current->depth + 1);
        }
        current = current->sons[seg];
    }
    current->message = proute;
}

stud_route_msg *route_find(unsigned int dest) {
    route_list_node *current = root;
    while (current->depth < 4) {
        unsigned char seg = ((dest >> ((3 - current->depth) * 8)) & 0xff);
        map<unsigned char, route_list_node*>::iterator iter = current->sons.find(seg);
        if (iter == current->sons.end()) {
            return NULL;
        }
        current = iter->second;
    }
    return current->message;
}

int stud_fwd_deal(char *pBuffer, int length) {
    // 不需要检验ip头部
    unsigned int dest_addr = ntohl(((ipv4_head *)pBuffer)->destination_address);
    stud_route_msg *message = route_find(dest_addr);
    if (message == NULL) {
        fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_NOROUTE);
        return 1;
    }
    unsigned short ttl = (((ipv4_head *)pBuffer)->TTL_protocol >> 4) & 0xff - 1;
    if (ttl == 0) {
        fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_TTLERROR);
        return 1;
    }
    ((ipv4_head *)pBuffer)->header_checksum += (unsigned short) 0x0100;
    ((ipv4_head *)pBuffer)->TTL_protocol = (ttl << 4) | (((ipv4_head *)pBuffer)->TTL_protocol) & 0xff;
    
    if (dest_addr == getIpv4Address()) {
        fwd_LocalRcv(pBuffer, length);
    } else {
        fwd_SendtoLower(pBuffer, length, message->nexthop);
    }
    return 0;
}