#ifndef CONNSTATE_H
#define CONNSTATE_H

#include <pcap.h>

struct ConnState {
    int sndSock;
    int rcvSock;
    u_int32_t srcAddr;
    char *outPkt;
    pcap_t *handle;
};

#endif
