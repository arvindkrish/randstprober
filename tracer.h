#ifndef TRACER_H
#define TRACER_H

#include "connstate.h"

extern "C" {
    struct ConnState InitConnection(char *device);

    void SendSingleProbe(int sndSock,
			 u_int32_t srcAddr,
			 u_int32_t destAddr,
			 char *outPkt,
			 int ttl,
			 int seq,
			 struct timeval *sendTime,
			 struct timeval *sendPcapTime,
			 pcap_t *pcapHandle);

    void SendPaddedProbe(int size,
			 int sndSock,
			 u_int32_t srcAddr,
			 u_int32_t destAddr,
			 char *outPkt,
			 int ttl,
			 int seq,
			 struct timeval *sendTime,
			 struct timeval *sendPcapTime,
			 pcap_t *pcapHandle);


    int ReceivePacket(int rcvSock,
		      struct sockaddr_in *from,
		      struct timeval *wait,
		      struct timeval *recvTime,
		      char *packet,
		      int *rcvSeq,
		      int *retTtl,
		      u_int32_t *retSrc);

    double deltaT(struct timeval *, struct timeval *);
    void	tvsub(struct timeval *, struct timeval *);
};

#endif
