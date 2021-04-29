#include "sysinclude.h"
// #include <arpa/inet.h>
#include <iostream>
#include <cstdio>
#include <list>
#include <vector>
#include <algorithm>
#include <deque>

using namespace std;

extern void SendFRAMEPacket(unsigned char* pData, unsigned int len);

typedef char uint_8;
typedef enum { data, ack, nak } frame_kind;
// enum { MSG_TYPE_TIMEOUT, MSG_TYPE_SEND, MSG_TYPE_RECEIVE };

struct frame_head {
    frame_kind kind;
    unsigned int seq;
    unsigned int ack;
    unsigned char data[100];
};

struct frame {
    frame_head head;
    int size;
};

struct store_frame {
    frame f;
    unsigned int size;
    store_frame() {}
    store_frame(frame _frame, int _size): f(_frame), size(_size) {}
};

int stud_slide_window_stop_and_wait(char *pBuffer, int bufferSize, uint_8 messageType) {
    static vector<store_frame> frame_list;
    static int expect = 0;
    switch (messageType) {
        case MSG_TYPE_TIMEOUT: {
            uint32_t timeout_seq = *(uint32_t *)(pBuffer);
            store_frame send_frame = frame_list[expect];
            printf("Timeout, resend %d\n", timeout_seq);
            SendFRAMEPacket((unsigned char *)(&(send_frame.f)), send_frame.size);
            break;
        }
        case MSG_TYPE_RECEIVE: {
            store_frame send_frame = frame_list[expect];
            frame ack_frame = *(frame *)(pBuffer);
            printf("Receive ack %d\n", ntohl(ack_frame.head.ack));
            while (send_frame.f.head.seq <= ack_frame.head.ack) {
                expect++;
                send_frame = frame_list[expect];
            }
            printf("Send a new frame %d\n", ntohl(send_frame.f.head.seq));
            SendFRAMEPacket((unsigned char *)&(send_frame.f), send_frame.size);
            break;
        }
        case MSG_TYPE_SEND: {
            //需要发送这一个帧
            frame *send_frame = (frame *)(pBuffer);
            printf("Frame info: %d,%d\n", ntohl(send_frame->head.seq), send_frame->head.data);
            frame_list.push_back(store_frame(*send_frame, bufferSize));
            if (expect == frame_list.size() - 1) {
                printf("Sending frame %d...\n", ntohl(send_frame->head.seq));
                SendFRAMEPacket((unsigned char *)send_frame, bufferSize);
            } else {
                printf("Waiting frame %d...\n", ntohl(send_frame->head.seq));
            }
            break;
        }
    }
    return 0;
}

int stud_slide_window_back_n_frame(char *pBuffer, int bufferSize, uint_8 messageType) {
    static const int window_size = 4;
    static vector<store_frame> frame_list;
    static int window_begin, window_end;
    
    switch (messageType) {
        case MSG_TYPE_TIMEOUT: {
            uint32_t timeout_seq = *(uint32_t *)(pBuffer);
            printf("Timeout seq: %d\n", timeout_seq);
            for (int i = window_begin; i < window_end; i++) {
                printf("Timeout, resend %d\n", ntohl(frame_list[i].f.head.seq));
                SendFRAMEPacket((unsigned char *)(&(frame_list[i].f)), frame_list[i].size);
            }
            break;
        }
        case MSG_TYPE_RECEIVE: {
            frame ack_frame = *(frame *)(pBuffer);
            for (int i = window_begin; i < window_end; i++) {
                if (frame_list[i].f.head.seq == ack_frame.head.ack) {
                    for (int j = window_end; j < i + 1 + window_size, j < frame_list.size(); j++) {
                        printf("Opening window, sending %d\n", ntohl(frame_list[j].f.head.seq));
                        SendFRAMEPacket((unsigned char *)(&(frame_list[j].f)), frame_list[j].size);
                    }
                    window_begin = i + 1;
                    window_end = min((int)frame_list.size(), window_begin + window_size);
                    break;
                }
            }
            break;
        }
        case MSG_TYPE_SEND: {
            frame *send_frame = (frame *)(pBuffer);
            frame_list.push_back(store_frame(*send_frame, bufferSize));
            if (frame_list.size() <= window_size) {
                window_end++;
                printf("Sending frame %d...\n", ntohl(send_frame->head.seq));
                SendFRAMEPacket((unsigned char *)send_frame, bufferSize);
            } else {
                printf("Waiting frame %d...\n", ntohl(send_frame->head.seq));
            }
            break;
        }
    }
    return 0;
}

int stud_slide_window_choice_frame_resend(char *pBuffer, int bufferSize, uint_8 messageType) {
    static const int window_size = 4;
    static vector<store_frame> frame_list;
    static int window_begin, window_end;

    switch (messageType) {
        case MSG_TYPE_TIMEOUT: {
            uint32_t timeout_seq = *(uint32_t *)(pBuffer);
            printf("Timeout seq: %d\n", timeout_seq);
            for (int i = window_begin; i < window_end; i++) {
                printf("Timeout, resend %d\n", ntohl(frame_list[i].f.head.seq));
                SendFRAMEPacket((unsigned char *)(&(frame_list[i].f)), frame_list[i].size);
            }
            break;
        }
        case MSG_TYPE_RECEIVE: {
            frame ack_frame = *(frame *)(pBuffer);
            if (ntohl(ack_frame.head.kind) == ack) {
                printf("Receive ack %d\n", ntohl(ack_frame.head.ack));
                for (int i = window_begin; i < window_end; i++) {
                    if (frame_list[i].f.head.seq == ack_frame.head.ack) {
                        for (int j = window_end; j < i + 1 + window_size, j < frame_list.size(); j++) {
                            printf("Opening window, sending %d\n", ntohl(frame_list[j].f.head.seq));
                            SendFRAMEPacket((unsigned char *)(&(frame_list[j].f)), frame_list[j].size);
                        }
                        window_begin = i + 1;
                        window_end = min((int)frame_list.size(), window_begin + window_size);
                        break;
                    }
                }
            }
            else if (ntohl(ack_frame.head.kind) == nak) {
                printf("Receive ack %d\n", ntohl(ack_frame.head.ack));
                for (int i = window_begin; i < window_end; i++) {
                    if (frame_list[i].f.head.seq == ack_frame.head.ack) {
                        printf("Error, resend %d\n", ntohl(ack_frame.head.ack));
                        SendFRAMEPacket((unsigned char *)(&(frame_list[i].f)), frame_list[i].size);
                        break;
                    }
                }
            }
            break;
        }
        case MSG_TYPE_SEND: {
            frame *send_frame = (frame *)(pBuffer);
            frame_list.push_back(store_frame(*send_frame, bufferSize));
            if (frame_list.size() <= window_size) {
                window_end++;
                printf("Sending frame %d...\n", ntohl(send_frame->head.seq));
                SendFRAMEPacket((unsigned char *)send_frame, bufferSize);
            } else {
                printf("Waiting frame %d...\n", ntohl(send_frame->head.seq));
            }
            break;
        }
    }
    return 0;
}
