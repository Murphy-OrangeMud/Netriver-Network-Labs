// 实现一个客户端TCP状态机（在客户端实现传输层协议）
#define LOCAL

#include <iostream>
#include <cstdio>
#ifdef LOCAL
#include <arpa/inet.h>
#endif
#include <vector>
#include <cstring>
#include <deque>
#ifndef LOCAL
#include "sysinclude.h"
#endif
using namespace std;

#ifdef LOCAL
typedef short uint16;
typedef char uint8;
typedef unsigned int uint32;
#endif

extern void tcp_DiscardPkt(char *pBuffer, int type);
extern void tcp_sendIpPkt(unsigned char *pData, uint16 len, unsigned int srcAddr, unsigned int dstAddr, uint8 ttl);
// only for socket API
// 本函数用于学生代码中主动接收 IP 分组，如果在设定时间内正确接收到分组，则将该分组内容复制到 pBuffer 中，否则返回－1
extern int waitIpPacket(char *pBuffer, int timeout);
extern uint32 getIpv4Address();
extern uint32 getServerIpv4Address();

int gSrcPort = 2007;
int gDstPort = 2006;
int gSeqNum = 1;
int gAckNum = 0;

const int BUFFERSIZE = 1024;
const int TIMEOUT = 5000; 

#ifdef LOCAL
// system defined
enum TypeFlag {
    PACKET_TYPE_DATA,
    PACKET_TYPE_SYN,
    PACKET_TYPE_SYN_ACK,
    PACKET_TYPE_ACK,
    PACKET_TYPE_FIN,
    PACKET_TYPE_FIN_ACK
};

// system defined
enum ErrorType {
    STUD_TCP_TEST_SEQNO_ERROR,
    STUD_TCP_TEST_SRCPORT_ERROR,
    STUD_TCP_TEST_DSTPORT_ERROR
};
#endif

enum State {
    CLOSED,
    SYN_SENT,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    TIME_WAIT,
    CLOSING
};

struct Socket {
    int sockno;
    int domain;
    int type;
    int protocol;
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t srcAddr;
    uint32_t dstAddr;
    int seq;
    int ack;
    State curstate;
};
vector<Socket> sockets;

struct tcp_wait {
    char *packet;
    size_t totallen;
    tcp_wait() {}
    tcp_wait(char *_p, size_t _t): packet(_p), totallen(_t) {}
};
deque<tcp_wait> waitpacket;

static int canSend = 1;

// tcp packet send
// TODO: 判断是否可以发送
/*
 * 学生需要在此函数中自行申请一定的空间，并封装 TCP 头和相关的数
 * 据，此函数可以由接收函数调用，也可以直接由解析器调用，此函数中将调
 * 用 tcp_sendIpPkt 完成分组发送。
 */
void stud_tcp_output(char *pData, // 数据指针
                     unsigned short len, // 数据长度 
                     unsigned char flag, // 分组类型
                     unsigned short srcPort, 
                     unsigned short dstPort, 
                     unsigned int srcAddr, 
                     unsigned int dstAddr) {

    int cursock = 0;
    for (; cursock < sockets.size(); cursock++) {
        if (sockets[cursock].srcAddr = srcAddr && sockets[cursock].dstAddr == dstAddr && sockets[cursock].srcPort == srcPort && sockets[cursock].dstPort == dstPort) {
            break;
        }
    }
    if (cursock >= sockets.size()) {
        // create a new sock
        cursock = stud_tcp_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockets[cursock - 3].dstAddr = dstAddr;
        sockets[cursock - 3].dstPort = dstPort;
        sockets[cursock - 3].srcAddr = srcAddr;
        sockets[cursock - 3].srcPort = srcPort;
        sockets[cursock - 3].seq = gSeqNum;
        sockets[cursock - 3].ack = gAckNum;
    } else {
        cursock += 3;
    }

    // debug
    printf("stud_tcp_output:%d %d %d\n", flag, sockets[cursock - 3].seq, sockets[cursock - 3].ack);

    char *pBuffer;
    pBuffer = (char *)malloc(len + 20);
    memset(pBuffer, 0, len+20);
    ((unsigned short *)pBuffer)[0] = htons(srcPort);
    ((unsigned short *)pBuffer)[1] = htons(dstPort);
    ((unsigned long *)pBuffer)[1] = htonl(sockets[cursock - 3].seq);
    ((unsigned long *)pBuffer)[2] = htonl(sockets[cursock - 3].ack);
    
    // head len
    pBuffer[12] = 0x50;
    // window size
    ((unsigned short *)pBuffer)[7] = htons(1);
    
    switch (flag) {
        case PACKET_TYPE_DATA: {
            pBuffer[13] = 0;
            break;
        }
        case PACKET_TYPE_SYN: {
            pBuffer[13] = 0x02;
            break;
        }
        case PACKET_TYPE_SYN_ACK: {
            pBuffer[13] = 0x12;
            break;
        }
        case PACKET_TYPE_ACK: {
            pBuffer[13] = 0x10;
            break;
        }
        case PACKET_TYPE_FIN: {
            pBuffer[13] = 0x01;
            break;
        }
        case PACKET_TYPE_FIN_ACK: {
            pBuffer[13] = 0x11;
            break;
        }
    }

    // 校验和
    unsigned int sum = 0;
    for (int i = 0; i < (unsigned int)(pBuffer[12] >> 4) * 4; i += 2) {
        sum += (*((unsigned short *)(pBuffer + i)));
    }
    // 加上伪头
    sum += htons((unsigned short)(srcAddr & 0xffff));
    sum += htons((unsigned short)(srcAddr >> 16));
    sum += htons((unsigned short)(dstAddr & 0xffff));
    sum += htons((unsigned short)(dstAddr >> 16));
    sum += htons(0x0006); // TCP协议号为6
    int mlen = len + 20; // 伪头
    if (mlen % 2) mlen += 1;
    sum += htons(mlen);
    // 加上身体！！！
    for (int i = 0; i < len; i += 2) {
        sum += (*((unsigned short *)(pBuffer + i + 20)));
    }
    sum = (sum & 0xffff) + (sum >> 16);
    unsigned short sum2 = ~sum;
    ((unsigned short *)pBuffer)[8] = sum2;

    // debug
    printf("stud_tcp_output: checksum: %d %d\n", sum2, htons(sum2));

    // data
    if (pData) {
        memcpy(pBuffer + 20, pData, sizeof(len));
    }

    tcp_sendIpPkt((unsigned char *)pBuffer, len + 20, srcAddr, dstAddr, 255);
}

// tcp packet receive
/*
 * 所有接收到的 TCP 报文都将调用本函数传递给学生代码，本函数中学
 * 生需要维护一个状态机，并根据状态机得变迁调用 stud_TCP_send 向服务器
 * 发送对应的报文，如果出现异常，则需要调用 tcp_sendReport 函数向服务器
 * 报告处理结果
 */
int stud_tcp_input(char *pBuff, 
                   unsigned short len, 
                   unsigned int srcAddr, 
                   unsigned int dstAddr) {

    printf("stud_tcp_input: \n");

    // 参数提供的源和目的ip地址的转换
    unsigned int tmp = srcAddr;
    srcAddr = htonl(dstAddr);
    dstAddr = htonl(tmp);

    int cursock = 0;
    for (; cursock < sockets.size(); cursock++) {
        if (sockets[cursock].srcAddr = srcAddr && sockets[cursock].dstAddr == dstAddr && sockets[cursock].srcPort == gSrcPort && sockets[cursock].dstPort == gDstPort) {
            break;
        }
    }
    if (cursock >= sockets.size()) {
        // create a new sock
        cursock = stud_tcp_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockets[cursock - 3].dstAddr = dstAddr;
        sockets[cursock - 3].dstPort = gDstPort;
        sockets[cursock - 3].srcAddr = srcAddr;
        sockets[cursock - 3].srcPort = gSrcPort;
        sockets[cursock - 3].seq = gSeqNum;
        sockets[cursock - 3].ack = gAckNum;
    } else {
        cursock += 3;
    }
    
    if (ntohs(((unsigned short *)pBuff)[0]) != gDstPort) { // 收到报文的源端口是服务器的端口
        tcp_DiscardPkt(pBuff, STUD_TCP_TEST_SRCPORT_ERROR);
        return -1;
    }
    if (ntohs(((unsigned short *)pBuff)[1]) != gSrcPort) {
        tcp_DiscardPkt(pBuff, STUD_TCP_TEST_DSTPORT_ERROR);
        return -1;
    }

    if (ntohl(((unsigned long *)pBuff)[2]) != sockets[cursock - 3].seq + 1) {
        tcp_DiscardPkt(pBuff, STUD_TCP_TEST_SEQNO_ERROR);
        return -1;
    }

    // 检查校验和 
    unsigned int sum = 0;
    // 加上伪头
    sum += htons((unsigned short)(srcAddr & 0xffff));
    sum += htons((unsigned short)(srcAddr >> 16));
    sum += htons((unsigned short)(dstAddr & 0xffff));
    sum += htons((unsigned short)(dstAddr >> 16));
    sum += htons(0x0006); // 协议号为17
    int mlen = len; // 伪头
    if (mlen % 2) mlen += 1;
    sum += htons(mlen);
    // 加上身体！！！
    for (int i = 0; i < len; i += 2) {
        sum += (*((unsigned short *)(pBuff + i)));
    }
    sum = (sum & 0xffff) + (sum >> 16);
    unsigned short sum2 = ~sum;
    
    // debug
    printf("stud_tcp_input: checksum: %d %d\n", sum2, htons(sum2));

    // 转换字节序
    ((unsigned short *)pBuff)[0] = sockets[cursock - 3].dstPort;
    ((unsigned short *)pBuff)[1] = sockets[cursock - 3].srcPort;
    ((unsigned long *)pBuff)[1] = ntohl(((unsigned long *)pBuff)[1]);
    ((unsigned long *)pBuff)[2] = sockets[cursock - 3].seq + 1;

    // 假定其他无关比特全是0
    switch (pBuff[13] & 0xff) {
        case 0x11: {
            // FIN_ACK
            // FIN
            sockets[cursock - 3].ack = ((unsigned long *)pBuff)[1] + 1;
            sockets[cursock - 3].seq++;
            stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, sockets[cursock - 3].srcPort, sockets[cursock - 3].dstPort, srcAddr, dstAddr);
            break;
        }
        case 0x10: {
            break;
        }
        case 0x12: {
            // SYN ACK
            // SYN
            sockets[cursock - 3].ack = ((unsigned long *)pBuff)[1] + 1;
            sockets[cursock - 3].seq++;
            stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, sockets[cursock - 3].srcPort, sockets[cursock - 3].dstPort, srcAddr, dstAddr);
            break;
        }
        case 0x01: {
            // FIN
            sockets[cursock - 3].ack = ((unsigned long *)pBuff)[1] + 1;
            sockets[cursock - 3].seq++;
            stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, sockets[cursock - 3].srcPort, sockets[cursock - 3].dstPort, srcAddr, dstAddr);
            break;
        }
        case 0x02: {
            // SYN
            sockets[cursock - 3].ack = ((unsigned long *)pBuff)[1] + 1;
            sockets[cursock - 3].seq++;
            stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, sockets[cursock - 3].srcPort, sockets[cursock - 3].dstPort, srcAddr, dstAddr);
            break;
        }
        case 0x00: {
            // DATA
            sockets[cursock - 3].ack = ((unsigned long *)pBuff)[1] + 1;
            sockets[cursock - 3].seq++;
            stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, sockets[cursock - 3].srcPort, sockets[cursock - 3].dstPort, srcAddr, dstAddr);
            break;
        }
    }

    return 0;
}

// 返回以后在系统调用中可能用到的 socket 描述符，或者在错误的时候返回-1
int stud_tcp_socket(int domain,  // 套接字标志符，缺省为 INET
                    int type,  // 类型，缺省为 SOCK_STREAM
                    int protocol) // 协议，缺省为 IPPROTO_TCP
{
    // debug
    printf("stud_tcp_socket\n");

    int sockno = 0;
    Socket socket;
    for (; sockno < sockets.size(); sockno++) {
        if (sockets[sockno].curstate == CLOSED) {
            break;
        } 
    }
    if (sockets.size() > sockno) {
        socket = sockets[sockno];
    }
    sockno += 3;

    socket.curstate = CLOSED;
    socket.sockno = sockno; // stdin, stdout, stderr
    
    socket.domain = domain;
    socket.type = type;
    socket.protocol = protocol;

    socket.srcAddr = getIpv4Address();
    socket.dstAddr = getServerIpv4Address();
    socket.srcPort = gSrcPort;
    socket.dstPort = gDstPort;

    socket.seq = gSeqNum;
    socket.ack = gAckNum;

    // debug
    printf("stud_tcp_socket: sockno: %d, srcaddr: %x, dstaddr: %x\n", socket.sockno, socket.srcAddr, socket.dstAddr);

    sockets.push_back(socket);
    return socket.sockno;
}

// 如果正确发送则返回 0，否则返回-1
// 在本函数中要求发送 SYN 报文，并调用 waitIpPacket 函数获得SYN_ACK 报文，并发送 ACK 报文，直至建立 tcp 连接。
int stud_tcp_connect(int sockfd, // 套接字标志符
                     struct sockaddr_in *addr, // socket 地址结构指针
                     int addrlen) // 地址结构的大小
{
    // debug
    printf("stud_tcp_connect: %d\n", sockfd);

    if (sockfd < 3 || sockfd >= sockets.size() + 3) {
        printf("Invalid sockfd, connect failed\n");
        return -1;
    }

    if (sockets[sockfd - 3].curstate != CLOSED) {
        printf("Already connected, connect failed\n");
        return -1;
    }

    // 设置状态
    sockets[sockfd - 3].curstate = SYN_SENT;
    sockets[sockfd - 3].dstAddr = ntohl(addr->sin_addr.s_addr);
    sockets[sockfd - 3].dstPort = ntohs(addr->sin_port);
    stud_tcp_output(NULL, 0, PACKET_TYPE_SYN, sockets[sockfd - 3].srcPort, sockets[sockfd - 3].dstPort, sockets[sockfd - 3].srcAddr, sockets[sockfd - 3].dstAddr);
    // log
    printf("Sent syn packet\n");

    char *recv = (char *)malloc(BUFFERSIZE);
    int err = waitIpPacket(recv, TIMEOUT);

    if (err == -1) {
        printf("Timeout when trying to connect, connect failed\n");
        return -1;
    }
    if (!((recv[13] & 0x10) && (recv[13] & 0x02))) { // SYN & ACK 
        printf("Receive type error, not SYN+ACK, connect failed\n");
        return -1;
    }

    // 同步，初始化SeqNum和AckNum
    sockets[sockfd - 3].seq = ntohl(((unsigned long *)recv)[2]);
    sockets[sockfd - 3].ack = ntohl(((unsigned long *)recv)[1]) + 1;

    // log
    printf("Successfully connect\n");

    stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, sockets[sockfd - 3].srcPort, sockets[sockfd - 3].dstPort, sockets[sockfd - 3].srcAddr, sockets[sockfd - 3].dstAddr);

    // 转移状态
    sockets[sockfd - 3].curstate = ESTABLISHED;
    return 0;
}

// 本函数向服务器发送数据“this is a tcp test”，在本函数内要调用 waitIpPacket 函数获得 ACK。
// 如果正确发送则返回 0，否则返回-1
// TODO: flags是干嘛的
int stud_tcp_send(int sockfd, // 套接字标志符
                  const unsigned char *pData, // 数据缓冲区指针
                  unsigned short datalen, // 数据长度
                  int flags) // 标志
{
    // debug
    printf("stud_tcp_send\n");

    int err;

    if (sockfd < 3 || sockfd >= sockets.size() + 3) {
        printf("Invalid socket fd, send failed\n");
        return -1;
    }
    if (sockets[sockfd - 3].curstate != ESTABLISHED) {
        printf("Connection not established, sent failed\n");
        return -1;
    }

    stud_tcp_output((char *)pData, datalen, PACKET_TYPE_DATA, sockets[sockfd - 3].srcPort, sockets[sockfd - 3].dstPort, sockets[sockfd - 3].srcAddr, sockets[sockfd - 3].dstAddr);

    char *recv_ack = (char *)malloc(BUFFERSIZE);
    err = waitIpPacket(recv_ack, TIMEOUT);
    if (err == -1) {
        printf("Timeout not ack, send failed\n");
        return -1;
    }

    sockets[sockfd - 3].ack = ntohl(((unsigned long *)recv_ack)[1]) + 1;
    sockets[sockfd - 3].seq = ntohl(((unsigned long *)recv_ack)[2]);

    return 0;
}

// 如果正确接收则返回 0，否则返回-1
// 本函数接收从服务器发送的数据，在本函数内要调用 sendIpPkt函数发送 ACK。
int stud_tcp_recv(int sockfd, unsigned char *pData, uint16 dataLen, int flags) {

    // debug
    printf("stud_tcp_recv\n");

    int err;

    if (sockfd < 3 || sockfd >= sockets.size() + 3) {
        printf("Invalid socket fd, recv failed\n");
        return -1;
    }
    if (sockets[sockfd - 3].curstate != ESTABLISHED) {
        printf("Connection not established, recv failed\n");
        return -1;
    }

    char *recv_data = (char *)malloc(BUFFERSIZE);
    err = waitIpPacket(recv_data, TIMEOUT);
    if (err == -1) {
        printf("Timeout, recv failed\n");
        return -1;
    }

    memcpy(pData, (char *)(recv_data + (4 * (unsigned int)(recv_data[12] >> 4))), dataLen);
    sockets[sockfd - 3].ack = ((unsigned long *)recv_data)[1] + 1;
    sockets[sockfd - 3].seq++;
    stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, sockets[sockfd - 3].srcPort, sockets[sockfd - 3].dstPort, sockets[sockfd - 3].srcAddr, sockets[sockfd - 3].dstAddr);
    return 0;
}

// 如果正常关闭则返回 0，否则返回-1
// 在本函数中要求发送 FIN 报文，并调用 waitIpPacket 函数获得 FIN_ACK报文，并发送 ACK 报文，直至关闭 tcp 连接
int stud_tcp_close(int sockfd) {

    // debug
    printf("stud_tcp_close\n");

    int err;

    if (sockfd < 3 || sockfd >= sockets.size() + 3) {
        printf("Invalid sockfd, close failed\n");
        return -1;
    }

    if (sockets[sockfd - 3].curstate != ESTABLISHED) {
        printf("Not connected, close failed\n");
        return -1;
    }

    // 转移状态
    sockets[sockfd - 3].curstate = FIN_WAIT_1;    
    stud_tcp_output(NULL, 0, PACKET_TYPE_FIN, sockets[sockfd - 3].srcPort,sockets[sockfd - 3].dstPort, sockets[sockfd - 3].srcAddr, sockets[sockfd - 3].dstAddr);
    // log
    printf("Sent fin packet\n");

    char *recv_ack = (char *)malloc(BUFFERSIZE);
    err = waitIpPacket(recv_ack, TIMEOUT);

    if (err == -1) {
        printf("Timeout when trying to close, close failed\n");
        return -1;
    }
    if (!(recv_ack[13] & 0x10)) { // ACK
        printf("Receive type error, not ACK, close failed\n");
        return -1;
    }

    // 状态转换
    sockets[sockfd - 3].curstate = FIN_WAIT_2;
    
    char *recv_fin = (char *)malloc(BUFFERSIZE);
    err = waitIpPacket(recv_fin, TIMEOUT);

    if (err == -1) {
        printf("Timeout when trying to close, close failed\n");
        return -1;
    }
    if (!(recv_fin[13] & 0x1)) { // FIN 
        printf("Receive type error, not FIN, close failed\n");
        return -1;
    }
    
    sockets[sockfd - 3].ack = ntohl(((unsigned long *)recv_fin)[1]) + 1;
    sockets[sockfd - 3].seq = ntohl(((unsigned long *)recv_fin)[2]);
    stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, sockets[sockfd - 3].srcPort, sockets[sockfd - 3].dstPort, sockets[sockfd - 3].srcAddr, sockets[sockfd - 3].dstAddr);

    // 状态转移
    sockets[sockfd - 3].curstate = TIME_WAIT;

    char *timeout_recv = (char *)malloc(BUFFERSIZE);
    err = waitIpPacket(timeout_recv, TIMEOUT);
    
    if (err != -1) {
        printf("Server send message, close failed\n");
        return -1;
    }

    // 转移状态
    sockets[sockfd - 3].curstate = CLOSED;

    // 释放连接
    sockets[sockfd - 3].domain = -1;
    sockets[sockfd - 3].type = -1;
    sockets[sockfd - 3].dstAddr = 0;
    sockets[sockfd - 3].srcAddr = 0;
    sockets[sockfd - 3].dstPort = 0;
    sockets[sockfd - 3].srcPort = 0;
    sockets[sockfd - 3].protocol = 0;

    // log
    printf("Successfully closed\n");
    return 0;
}
