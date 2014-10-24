#include "preamble.h"
#include <sys/param.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <net/ethernet.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <memory.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <assert.h>

#include "gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

/* rfc1716 */
#ifndef ICMP_UNREACH_FILTER_PROHIB
#define ICMP_UNREACH_FILTER_PROHIB	13	/* admin prohibited filter */
#endif
#ifndef ICMP_UNREACH_HOST_PRECEDENCE
#define ICMP_UNREACH_HOST_PRECEDENCE	14	/* host precedence violation */
#endif
#ifndef ICMP_UNREACH_PRECEDENCE_CUTOFF
#define ICMP_UNREACH_PRECEDENCE_CUTOFF	15	/* precedence cutoff */
#endif

#include "findsaddr.h"
#include "ifaddrlist.h"
#include "traceroute.h"
#include "connstate.h"

#define Fprintf (void)fprintf
#define Printf (void)printf

/* Host name and address list */
struct hostinfo {
	char *name;
	int n;
	u_int32_t *addrs;
};

/* Data section of the probe packet */
struct outdata {
	u_char seq;		/* sequence number of this packet */
	u_char ttl;		/* ttl packet left with */
	struct timeval tv;	/* time packet left */
};


u_short ident;
u_short port = 32768 + 666;	/* start udp dest port # for probe packets */

/* Forwards */
u_short	in_cksum(u_short *, int);
void	tvsub(struct timeval *, struct timeval *);
#ifndef HAVE_USLEEP
int	usleep(u_int);
#endif

int useicmp = 1;
int recordroute = 0;

int // x - y
timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	 *      tv_usec is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}

double
deltaT(struct timeval *t1p, struct timeval *t2p) //t2 - t1
{
    struct timeval res;
    register double dt;

    timeval_subtract(&res, t2p, t1p);

    /*dt = (double)(t2p->tv_sec - t1p->tv_sec) * 1000.0 +
	(double)(t2p->tv_usec - t1p->tv_usec) / 1000.0;*/
    dt = res.tv_sec * 1000.0 + res.tv_usec / 1000.0;
    return (dt);
}


pcap_t *InitPcap(char *dev, char *filter_app)
{
    pcap_t *handle;			/* Session handle */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program filter;	/* The compiled filter */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    int ret;

    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
	fprintf(stderr, "Can't get netmask for device %s\n", dev);
	net = 0;
	mask = 0;
    }
    
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
    if (handle == NULL) {
	fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
	return NULL;
    }

    ret = pcap_setnonblock(handle, 1, errbuf);
    if (ret == -1) {
	fprintf(stderr, "Couldn't set nonblock: %s\n", errbuf);
	return NULL;
    }

    /* Compile and apply the filter */
    if (pcap_compile(handle, &filter, filter_app, 0, net) == -1) {
	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_app, pcap_geterr(handle));
	return NULL;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_app, pcap_geterr(handle));
	return NULL;
    }
    pcap_freecode(&filter);
    return handle;
}

int targ_ip_id;
u_int32_t targ_ip_addr;
struct timeval xmitTime;

void callback_fun(u_char *useless, const struct pcap_pkthdr* pkthdr,
		  const u_char* packet)
{
    int size_ethernet = sizeof(struct ether_header);
    struct ip *iphdr = (struct ip *)(packet + size_ethernet);

    if (iphdr->ip_id == htons(targ_ip_id)
	&& iphdr->ip_dst.s_addr == targ_ip_addr)
	xmitTime = pkthdr->ts;
}

struct timeval GetOutgoingTstamp(pcap_t *handle, int targ_id, u_int32_t dstAddr)
{
    struct timeval zeroTime = {0, 0};
    targ_ip_id = targ_id;
    targ_ip_addr = dstAddr;
    xmitTime = zeroTime;
    
    while (1) {
	int cnt = pcap_dispatch(handle, 1, callback_fun, NULL);
	if (cnt == 0) {
	    return zeroTime;
	}
	if (xmitTime.tv_sec > 0 || xmitTime.tv_usec > 0)
	    return xmitTime;
    }
}

struct ConnState InitConnection(char *device)
{
    int s;			/* receive (icmp) socket file descriptor */
    int sndsock;		/* send (udp/icmp) socket file descriptor */
    struct ip *outip;		/* last output (udp) packet */
    int packlen;		/* total length of packet */
 
    register const char *err;

    struct sockaddr_in s1, s2;
    register struct sockaddr_in *from = &s1;
    register struct sockaddr_in *to = &s2;
    
    register struct protoent *pe;
    static const char devnull[] = "/dev/null";
    
    packlen = sizeof(*outip);
    if (useicmp)
	packlen += 8;			/* XXX magic number */
    else
	packlen += sizeof(struct udphdr);

#define MAX_PACKET_SIZE 1600
    
    outip = (struct ip *)malloc(MAX_PACKET_SIZE);
    if (outip == NULL) {
	Fprintf(stderr, "tracer: malloc: %s\n", strerror(errno));
	exit(1);
    }
    memset((char *)outip, 0, packlen);

    
    ident = (getpid() & 0xffff) | 0x8000;

    if ((pe = getprotobyname("icmp")) == NULL) {
	Fprintf(stderr, "tracer: unknown protocol icmp\n");
	exit(1);
    }

    /* Insure the socket fds won't be 0, 1 or 2 */
    if (open(devnull, O_RDONLY) < 0 ||
	open(devnull, O_RDONLY) < 0 ||
	open(devnull, O_RDONLY) < 0) {
	Fprintf(stderr, "tracer: open \"%s\": %s\n",
		devnull, strerror(errno));
	exit(1);
    }
    if ((s = socket(AF_INET, SOCK_RAW, pe->p_proto)) < 0) {
	Fprintf(stderr, "tracer: icmp socket: %s\n", strerror(errno));
	exit(1);
    }
    sndsock = socket(AF_INET, SOCK_RAW, useicmp ? IPPROTO_ICMP : IPPROTO_UDP);
    if (sndsock < 0) {
	Fprintf(stderr, "tracer: raw socket: %s\n", strerror(errno));
	exit(1);
    }

#ifdef SO_SNDBUF
    if (setsockopt(sndsock, SOL_SOCKET, SO_SNDBUF, (char *)&packlen,
		   sizeof(packlen)) < 0) {
	Fprintf(stderr, "tracer: SO_SNDBUF: %s\n", strerror(errno));
	exit(1);
    }
#endif
#ifdef IP_HDRINCL
    {
	int on = 1;
	
	if (setsockopt(sndsock, IPPROTO_IP, IP_HDRINCL, (char *)&on,
		       sizeof(on)) < 0) {
	    Fprintf(stderr, "tracer: IP_HDRINCL: %s\n", strerror(errno));
	    exit(1);
	}
    }
#endif
    if ((err = findsaddr(to, from)) != NULL) {
	Fprintf(stderr, "tracer: findsaddr: %s\n", err);
	exit(1);
    }

    /* Revert to non-privileged user after opening sockets */
    setgid(getgid());
    setuid(getuid());


    {
	struct ConnState c;
	pcap_t *handle;
	
	c.sndSock = sndsock;
	c.rcvSock = s;
	c.outPkt = (char *)outip;
	c.srcAddr = from->sin_addr.s_addr;

	if (useicmp)
	    handle = InitPcap(device, "icmp[icmptype]=icmp-echo");
	else {
	    char filter[200];
	    sprintf(filter, "udp port %d", ident);
	    handle = InitPcap(device, filter);
	}

	c.handle = handle;
	return c;
    }
}



/*
 * Checksum routine for Internet Protocol family headers (C Version)
 */
u_short
in_cksum(register u_short *addr, register int len)
{
    register int nleft = len;
    register u_short *w = addr;
    register u_short answer;
    register int sum = 0;

    /*
     *  Our algorithm is simple, using a 32 bit accumulator (sum),
     *  we add sequential 16 bit words to it, and at the end, fold
     *  back all the carry bits from the top 16 bits into the lower
     *  16 bits.
     */
    while (nleft > 1)  {
	sum += *w++;
	nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1)
	sum += *(u_char *)w;

    /*
     * add back carry outs from top 16 bits to low 16 bits
     */
    sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
    sum += (sum >> 16);			/* add carry */
    answer = ~sum;				/* truncate to 16 bits */
    return (answer);
}

/*
 * Subtract 2 timeval structs:  out = out - in.
 * Out is assumed to be >= in.
 */
void
tvsub(register struct timeval *out, register struct timeval *in)
{
    struct timeval result;
    timeval_subtract (&result, out, in);
    *out = result;

/*    if ((out->tv_usec -= in->tv_usec) < 0)   {
	--out->tv_sec;
	out->tv_usec += 1000000;
    }
    out->tv_sec -= in->tv_sec;*/
}

void
setsin(register struct sockaddr_in *sin, register u_int32_t addr)
{

    memset(sin, 0, sizeof(*sin));
#ifdef HAVE_SOCKADDR_SA_LEN
    sin->sin_len = sizeof(*sin);
#endif
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = addr;
}


void	print(u_char *, int, struct sockaddr_in *);
int	wait_for_reply(int, struct sockaddr_in *, struct timeval *, char *);
int	chk_packet_ok(u_char *, int, struct sockaddr_in *, int *, int *, u_int32_t *);
int     send_probe(register int seq, int ttl, register struct timeval *tp,
		   int sndsock, u_int32_t srcAddr,
		   struct sockaddr_in *whereto, char *outPkt, int size);


void SendSingleProbe(int sndsock, u_int32_t srcAddr, u_int32_t destAddr,
		     char *outPkt, int ttl, int seq,
		     struct timeval *todTime, struct timeval *ptime,
		     pcap_t *pcapHandle)
{
    struct timeval zeroTime = {0, 0};
    struct timezone tz;
    struct ip *outip = (struct ip *)outPkt;
    struct sockaddr_in to;
    struct timeval pcapTime;

    setsin(&to, destAddr);
    outip->ip_dst = to.sin_addr;
    /*    printf("--> %s, hop: %d\n", inet_ntoa(to->sin_addr), ttl); */
    (void)gettimeofday(todTime, &tz);
    send_probe(seq, ttl, todTime, sndsock, srcAddr, &to, outPkt, 0);
#if 0
    if (useicmp)
	pcapTime = GetOutgoingTstamp(pcapHandle, ident + seq);
    else
	pcapTime = zeroTime;
#else
    pcapTime = zeroTime;
    pcapTime = GetOutgoingTstamp(pcapHandle, ident + seq, destAddr);
#endif
    *ptime = pcapTime;
}

void SendPaddedProbe(int size, int sndsock, u_int32_t srcAddr, u_int32_t destAddr,
		     char *outPkt, int ttl, int seq,
		     struct timeval *todTime, struct timeval *ptime,
		     pcap_t *pcapHandle)
{
    struct timeval zeroTime = {0, 0};
    struct timezone tz;
    struct ip *outip = (struct ip *)outPkt;
    struct sockaddr_in to;
    struct timeval pcapTime;

    setsin(&to, destAddr);
    outip->ip_dst = to.sin_addr;
    /*    printf("--> %s, hop: %d\n", inet_ntoa(to->sin_addr), ttl); */
    (void)gettimeofday(todTime, &tz);
    send_probe(seq, ttl, todTime, sndsock, srcAddr, &to, outPkt, size);
#if 0
    if (useicmp)
	pcapTime = GetOutgoingTstamp(pcapHandle, ident + seq);
    else
	pcapTime = zeroTime;
#else
    pcapTime = zeroTime;
    pcapTime = GetOutgoingTstamp(pcapHandle, ident + seq, destAddr);
#endif
    *ptime = pcapTime;
}

int numBytes = 0;
int numPackets = 0;

int ReceivePacket(int s, struct sockaddr_in *from,
		  struct timeval *wait, struct timeval *t2,
		  char *packet, int *rcvSeq, int *retTtl, u_int32_t *retSrc)
{
    int cc;
    int i = 0;
	    
    while ((cc = wait_for_reply(s, from, wait, packet)) != 0) {
	if (cc != 0) {
	    numBytes += cc;
	    numPackets++;
	}
	/* printf("got %d bytes\n", cc); */
	i = chk_packet_ok((u_char *)packet, cc, from, rcvSeq, retTtl, retSrc);
	/* Skip short packet */
	if (i == 0)
	    continue;

#if 0
	print(packet, cc, from);
	Printf("  %.3f ms", deltaT(t1, t2));
#endif
	break;
    }
    {
	int retval;
#ifdef BAD_TSTAMPS
	(void)gettimeofday(t2, NULL);
#else
	retval = ioctl(s, SIOCGSTAMP, t2);
	if (retval == -1)
	    (void)gettimeofday(t2, NULL);	    
#endif
    }
    if (cc == 0)
	return 0;
    return i;
}

#if 0
void SendProbes2(int s, struct sockaddr_in *from, u_int32_t ipAddr,
		 int sndsock, struct sockaddr_in *to, char *outPkt)
{
    int ttl;
    int first_ttl = 1;
    int max_ttl = 30;
    int probe;
    int nprobes = 3;
    int seq = 0;
    u_char packet[512];
    
    for (ttl = first_ttl; ttl <= max_ttl; ++ttl) {
	int got_there = 0;
	int unreachable = 0;

	Printf("%2d ", ttl);
	for (probe = 0; probe < nprobes; ++probe) {
	    struct timeval t1, t2, wait;
	    int ret;
	    int rcvSeq;
	    
	    SendSingleProbe(sndsock, ipAddr, outPkt, ttl, ++seq, &t1);
#define WAITTIME 2
	    wait.tv_sec = t1.tv_sec + WAITTIME;
	    wait.tv_usec = t1.tv_usec;
	    ret = ReceivePacket(s, from, &wait, &t2, packet, &rcvSeq);
	    if (ret == -2)
		got_there = 1;
	    else if (ret != -1)
		unreachable++;
	}
	if (probe == nprobes)
	    printf("*\n");
	else
	    printf("\n");
	if (got_there ||
	    (unreachable > 0 && unreachable >= nprobes - 1))
	    break;
    }
}
#endif

int send_probe(register int seq, int ttl, register struct timeval *tp,
	       int sndsock, u_int32_t srcAddr, struct sockaddr_in *whereto,
	       char *outPkt, int size)
{
    register int cc;
    register u_char *outp;
    struct ip *outip;
    struct icmp *outicmp;
    struct udphdr *outudp;    
    register struct udpiphdr *ui, *oui;
    struct ip tip;
    int packlen;
    register u_short off = 0;
    char *str = "URL:http://iplane.cs.washington.edu/pl_measurement.html Contact:iplane-support@cs.washington.edu";
    
    if (useicmp) {
	if (recordroute)
	    packlen = sizeof(*outip) + 40 + 8 + size;
	else
	    packlen = sizeof(*outip) + 8 + size;
    }
    else
	packlen = sizeof(*outip) + sizeof(*outudp) + size;

    if (size > strlen(str)) {
	int offset;
	if (useicmp) {
	    if (recordroute)
		offset = sizeof(*outip) + 40 + 8;
	    else
		offset = sizeof(*outip) + 8;
	} else
	    offset = sizeof(*outip) + sizeof(*outudp);
	strcpy(outPkt + offset, str);
    }
	
    outip = (struct ip *)outPkt;

    outip->ip_v = IPVERSION;
#ifdef BYTESWAP_IP_HDR
    outip->ip_len = htons(packlen);
    outip->ip_off = htons(off);
#else
    outip->ip_len = packlen;
    outip->ip_off = off;
#endif
    
    outp = (u_char *)(outip + 1);
    if (recordroute)
	outp = (u_char *)outp + 40;
    outip->ip_dst = whereto->sin_addr;
    outip->ip_src.s_addr = srcAddr;
    outip->ip_hl = (outp - (u_char *)outip) >> 2;
    outip->ip_ttl = ttl;
    outip->ip_tos = 0;
    
#ifndef __hpux
    outip->ip_id = htons(ident + seq);
#endif

    if (useicmp) {
	outip->ip_p = IPPROTO_ICMP;

	if (recordroute) {
	    char *rspace = (char *)outip + sizeof(*outip);
	    rspace[0] = IPOPT_NOP;
	    rspace[1+IPOPT_OPTVAL] = IPOPT_RR;
	    rspace[1+IPOPT_OLEN] = 39;
	    rspace[1+IPOPT_OFFSET] = IPOPT_MINOFF;
	}

	outicmp = (struct icmp *)outp;
	outicmp->icmp_type = ICMP_ECHO;
	outicmp->icmp_id = htons(ident - seq);

    } else {
	outip->ip_p = IPPROTO_UDP;

	outudp = (struct udphdr *)outp;
	outudp->uh_sport = htons(ident);
	outudp->uh_ulen =
	    htons((u_short)(packlen - sizeof(*outip)));
    }

    /*
     * In most cases, the kernel will recalculate the ip checksum.
     * But we must do it anyway so that the udp checksum comes out
     * right.
     */
    outip->ip_sum =
	in_cksum((u_short *)outip, outip->ip_hl);
    if (outip->ip_sum == 0)
	outip->ip_sum = 0xffff;

    outicmp = (struct icmp *)outp;
    outudp = (struct udphdr *)outp;

    if (useicmp)
	outicmp->icmp_seq = htons(seq);
    else
	outudp->uh_dport = htons(port + seq);

    if (useicmp) {
	/* Always calculate checksum for icmp packets */
	outicmp->icmp_cksum = 0;
	outicmp->icmp_cksum = in_cksum((u_short *)outicmp,
				       packlen - sizeof(*outip));
	/* printf("checksum: %d\n", outicmp->icmp_cksum); */
	if (outicmp->icmp_cksum == 0)
	    outicmp->icmp_cksum = 0xffff;
    } else {
	/* Checksum (we must save and restore ip header) */
	tip = *outip;
	ui = (struct udpiphdr *)outip;
	oui = (struct udpiphdr *)&tip;
	/* Easier to zero and put back things that are ok */
	memset((char *)ui, 0, sizeof(ui->ui_i));
	ui->ui_src = oui->ui_src;
	ui->ui_dst = oui->ui_dst;
	ui->ui_pr = oui->ui_pr;
	ui->ui_len = outudp->uh_ulen;
	outudp->uh_sum = 0;
	outudp->uh_sum = in_cksum((u_short *)ui, packlen);
	if (outudp->uh_sum == 0)
	    outudp->uh_sum = 0xffff;
	*outip = tip;
    }

    cc = sendto(sndsock, (char *)outip,
		packlen, 0, (struct sockaddr *)whereto, sizeof(*whereto));

    if (cc < 0 || cc != packlen)
	return -1;
    return 0;
}


float convert_time_to_ms(struct timeval t)
{
    return t.tv_sec*1000.0 + t.tv_usec/1000.0;
}

int wait_for_reply(register int sock, register struct sockaddr_in *fromp,
		   struct timeval *wait, char *packet)
{
    fd_set fds;
    struct timeval now;
    struct timeval t2 = *wait;
    register int cc = 0;
    int fromlen = sizeof(*fromp);

    FD_ZERO(&fds);
    FD_SET(sock, &fds);

    (void)gettimeofday(&now, NULL);
    tvsub(&t2, &now);
double twait = t2.tv_sec + t2.tv_usec*1.0e-6;
if(twait < 0) { t2.tv_sec = 0; t2.tv_usec = 10000; } //XXX: kvbp

    if (select(sock + 1, &fds, NULL, NULL, &t2) > 0)
	cc = recvfrom(sock, (char *)packet, MAX_PACKET_SIZE, 0,
		      (struct sockaddr *)fromp, (socklen_t *)&fromlen);
else printf("select timeout: %f s cc:%d\n", twait,cc); //XXX: kvbp
printf("\n");

    return(cc);
}

/*
 * Support for ICMP extensions
 *
 * http://www.ietf.org/proceedings/01aug/I-D/draft-ietf-mpls-icmp-02.txt
 */
#define ICMP_EXT_OFFSET    8 /* ICMP type, code, checksum, unused */ + \
                         128 /* original datagram */
#define ICMP_EXT_VERSION 2
/*
 * ICMP extensions, common header
 */
struct icmp_ext_cmn_hdr {
#if BYTE_ORDER == BIG_ENDIAN
       u_char   version:4;
       u_char   reserved1:4;
#else
       u_char   reserved1:4;
       u_char   version:4;
#endif
       u_char   reserved2;
       u_short  checksum;
};

/*
 * ICMP extensions, object header
 */
struct icmp_ext_obj_hdr {
    u_short length;
    u_char  class_num;
#define MPLS_STACK_ENTRY_CLASS 1
    u_char  c_type;
#define MPLS_STACK_ENTRY_C_TYPE 1
};

struct mpls_header {
#if BYTE_ORDER == BIG_ENDIAN
    u_int32_t label:20;
    u_char  exp:3;
    u_char  s:1;
    u_char  ttl:8;
#else
    u_char  ttl:8;
    u_char  s:1;
    u_char  exp:3;
    u_int32_t label:20;
#endif
};

/* return -2 if the destination is reached, -1 if there is
   a reply and there is chance of further progress.  if there
   is an error condition, return a positive value */
int chk_packet_ok(register u_char *buf, int cc,
		  register struct sockaddr_in *from,
		  int *seq, int *retTtl, u_int32_t *retSrc)
{
    register struct icmp *icp;
    register u_char type, code;
    register int hlen;
    int oldcc = cc;
#ifndef ARCHAIC
    register struct ip *ip;

    ip = (struct ip *) buf;
    hlen = ip->ip_hl << 2;
    if (cc < hlen + ICMP_MINLEN) {
	return (0);
    }
    cc -= hlen;
    icp = (struct icmp *)(buf + hlen);
#else
    icp = (struct icmp *)buf;
#endif
    type = icp->icmp_type;
    code = icp->icmp_code;

    /*    printf("***%d %s\n", ip->ip_ttl, inet_ntoa(ip->ip_src)); */
    if (retTtl) {
	*retTtl = ip->ip_ttl;
	if (oldcc > sizeof(struct ip) + ICMP_EXT_OFFSET) {
	    struct icmp_ext_cmn_hdr *cmn_hdr =
		(struct icmp_ext_cmn_hdr *)(buf + (ip->ip_hl << 2) + ICMP_EXT_OFFSET);
	    int datalen = oldcc - ((u_char *)cmn_hdr - (u_char *)ip);	    
	    if (cmn_hdr->version == ICMP_EXT_VERSION) {
		struct icmp_ext_obj_hdr *obj_hdr = (struct icmp_ext_obj_hdr *)(cmn_hdr + 1);
		datalen -= sizeof(*cmn_hdr);
		if (obj_hdr->class_num == MPLS_STACK_ENTRY_CLASS) {
		    /* printf("got mpls\n"); */
		    *retTtl += 256;
		}
	    }
	}
    }

    if ((type == ICMP_TIMXCEED && code == ICMP_TIMXCEED_INTRANS) ||
	type == ICMP_UNREACH || type == ICMP_ECHOREPLY) {
	register struct ip *hip;
	register struct udphdr *up;
	register struct icmp *hicmp;
	
	hip = &icp->icmp_ip;
	hlen = hip->ip_hl << 2;

	if (useicmp) {
	    /* XXX */
	    /*	    printf("got reply: %d %d %d\n", ident, ntohs(icp->icmp_id), ntohs(icp->icmp_seq)); */
	    if (type == ICMP_ECHOREPLY &&
		icp->icmp_id == htons(ident - ntohs(icp->icmp_seq)))
	    {
		*seq = ntohs(icp->icmp_seq);
#if 0
		printf("got echoreply ip-id %d %d\n", ntohs(ip->ip_id),
		       (int)hip->ip_ttl);
#endif
		return (-2);
	    }

#if 0
	    if (type == ICMP_TIMXCEED)
		printf("got ttl-exceeded %s %d\n",
		       inet_ntoa(ip->ip_src), ntohs(ip->ip_id));
#endif
		
	    
	    hicmp = (struct icmp *)((u_char *)hip + hlen);
	    /* printf("got reply: %d %d\n", ntohs(hicmp->icmp_id), ntohs(hicmp->icmp_seq)); */
	    
	    /* XXX 8 is a magic number */
	    if (hlen + 8 <= cc &&
		hip->ip_p == IPPROTO_ICMP &&
		hicmp->icmp_id == htons(ident - ntohs(hicmp->icmp_seq)))
  	    {
		*seq = ntohs(hicmp->icmp_seq);

#if 0
		printf("got %d type %s", type, inet_ntoa(ip->ip_src));

		printf(" %s %d %d\n", inet_ntoa(hip->ip_dst), ntohs(ip->ip_id), hip->ip_ttl);
#endif
		
		return (type == ICMP_TIMXCEED ? -1 : code + 1);
	    }
	} else {
	    up = (struct udphdr *)((u_char *)hip + hlen);
	    /* XXX 8 is a magic number */
	    if (hlen + 12 <= cc &&
		hip->ip_p == IPPROTO_UDP &&
		up->uh_sport == htons(ident))
	    {
		*seq = ntohs(up->uh_dport) - port;
#if 0
		if (type == ICMP_UNREACH_PORT)
		    printf("got port-unreachable %s %d %d\n",
			   inet_ntoa(ip->ip_src), ntohs(ip->ip_id), hip->ip_ttl);
		else if (type == ICMP_TIMXCEED)
		    printf("got ttl-exceeded %s %d\n",
			   inet_ntoa(ip->ip_src), ntohs(ip->ip_id));
#endif
		if (type == ICMP_UNREACH)
		    return (-2);
		
		return (type == ICMP_TIMXCEED ? -1 : code + 1);    
	    }
	}
    }
    return(0);
}

void
print(register u_char *buf, register int cc, register struct sockaddr_in *from)
{
    register struct ip *ip;
    register int hlen;

    ip = (struct ip *) buf;
    hlen = ip->ip_hl << 2;
    cc -= hlen;

    Printf(" %s", inet_ntoa(from->sin_addr));
}

