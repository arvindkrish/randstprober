#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "proberoute.h"
#include "tracer.h"
#include "util.h"
#include "socket-cpp.h"
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <net/ethernet.h>
#include <sys/time.h>
#include <map>

int clientId;
char *server;
int serverPort;
int uniqueId;
int aggressive;

extern int useicmp;
extern int recordroute;

time_t finishTime;

std::map <uint32_t, int> ttl_count[256]; //256 hops max

extern int LookupAS(struct in_addr ipAddr);
void (*pfindRateLimitHops)(DestList *dests, int tracedCopy[], int size) = NULL;

int FinishProbing(Destination *d)
{
    if (d->numHops >= MAX_HOPS)
	return 1;

#ifdef STOP_EARLY
    int currAS = LookupAS(d->hops[d->numHops-1].addr);
    if (currAS == d->destAs)
	return 1;
#endif
    
    int fails = 0;
    for (int i=d->numHops-1; i>=0; i--) {
	if (d->hops[i].state)
	    return 0;
	fails++;
	if (fails == MAX_FAILS)
	    return 1;
    }
    return 0;
}

static int nextDest = 0;

int GetNextRandomDest(DestList *dests, ProbePool *pool)
{
    int destNo;
#ifdef RANDOM
    do {
	destNo = random() % dests->NumDests();
    } while (pool->AlreadyInPool(destNo) || dests->DoneStatus(destNo));
    return destNo;
#else
    if (nextDest < dests->NumDests())
	return nextDest++;
    else
	return -1;
#endif
}

#include "hashtable.h"
HashTable *aliasmap;
HashTable *clustermap;

extern "C" {
    void ReadAsMapping(char *fname);
    int MapSingleAddress(in_addr_t addr, char **asnum);
};

int LookupAS(struct in_addr ipAddr)
{
    char *key = inet_ntoa(ipAddr);
    int info;
    if ((info = *(int *)aliasmap->Get(key)) == 0) {
	char *asnum;
	int retval = MapSingleAddress(ipAddr.s_addr, &asnum);
	if (retval)
	    sscanf(asnum, "%d", &info);
	else
	    info = 0;
    }
    return info;
}


void ReadAliasFile(char *fname)
{
    FILE *fp = fopen(fname, "r");
    char *res;
#define MAX_LINE_SIZE 300
    char line[MAX_LINE_SIZE];
    int num = 0;

    res = fgets(line, MAX_LINE_SIZE, fp);
    aliasmap = new HashTable(999983);
    while (res) {
	char ipAddr[40];
	int asnum;
	int info;
	assert(sscanf(line, "%s %d", ipAddr, &asnum) == 2);
	if ((info = *(int *)aliasmap->Get(ipAddr)) == 0) {
	    aliasmap->Put(ipAddr, (void *)asnum);
	}
	res = fgets(line, MAX_LINE_SIZE, fp);	
    }
}

#define BLOCK 100	/* keep consistent with params.h */
static int tracedDests[BLOCK];
static int numTraced = 0;

struct SendThreadArgs {
    char *buffer;
    int len;
};

void *SendResults(void *arg)
{
    struct SendThreadArgs *param = (struct SendThreadArgs *)arg;
    int s = NetMakeContact(server, serverPort);
    write_int(s, clientId);
    write_int(s, uniqueId);
    write_int(s, BLOCK);
    write_int(s, param->len);
    write_buf(s, param->buffer, param->len);
    close(s);
}

static FILE *outfp = NULL;
static int countRecords = 0;
char *traceFile;
char *countFile;

void *WriteResults(void *arg, int size)
{
    struct SendThreadArgs *param = (struct SendThreadArgs *)arg;
    if (outfp == NULL)
	outfp = fopen(traceFile, "a");
    fwrite(&clientId, sizeof(int), 1, outfp);
    fwrite(&uniqueId, sizeof(int), 1, outfp);
    int t = size;
    fwrite(&t, sizeof(int), 1, outfp);
    fwrite(&param->len, sizeof(int), 1, outfp);
    fwrite(param->buffer, param->len, 1, outfp);
    fflush(outfp);
    fclose(outfp); outfp = NULL;

    FILE *cntfile = fopen(countFile, "w");
    countRecords += size;
    fprintf(cntfile, "%d\n", countRecords);
    fclose(cntfile);
}

void CommunicateResults(DestList *dests, int tracedCopy[], int size)
{
    int i, j;
    char *buf = new char[2*size*30*12];
    char *buffer = buf;
    int len;
    pthread_t tid;
    struct SendThreadArgs *arg = new (struct SendThreadArgs);

    /*    printf("writing %d records\n", size); */
    for (i=0; i<size; i++) {
	struct in_addr ip;
	int destNo = tracedCopy[i];
	inet_aton(dests->GetDestName(destNo), &ip);
	*(unsigned int *)buffer = ip.s_addr;
	buffer += sizeof(int);
	*(int *)buffer = dests->DestHops(destNo);
	buffer += sizeof(int);
	/*	printf("destination: %s hops: %d\n", inet_ntoa(ip), dests->DestHops(destNo)); */
	for (j=0; j<dests->DestHops(destNo); j++) {
	    struct in_addr router;
	    float lat;
	    int retTtl;
	    int numProbes;
            long sendtime;
	    if (!dests->HopStatus(destNo, j, &router, &lat, &retTtl, &numProbes, &sendtime)) {
		router.s_addr = 0;
		lat = 0;
		retTtl = 0;
	    }
	    *(unsigned int *)buffer = router.s_addr;
	    buffer += sizeof(int);
	    *(float *)buffer = lat;
	    buffer += sizeof(float);
	    *(int *)buffer = retTtl;
	    buffer += sizeof(int);
           *(long *)buffer = sendtime;
            buffer += sizeof(long);
	}
    }

    arg->buffer = buf;
    arg->len = buffer - buf;
    /*    pthread_create(&tid, NULL, SendResults, arg); */
    /* SendResults(arg); */
    WriteResults(arg, size);
    delete arg;
    delete [] buf;
}

void CommunicateResultsText(DestList *dests, int tracedCopy[], int size)
{
    int i, j;
    int len;

    if (outfp == NULL)
	outfp = fopen(traceFile, "a");

//    if(outfp == NULL) return;

    /*    printf("writing %d records\n", size); */
    for (i=0; i<size; i++) {
	struct in_addr ip;
	int destNo = tracedCopy[i];
	inet_aton(dests->GetDestName(destNo), &ip);
	fprintf(outfp, "D %s n %d\n", inet_ntoa(ip), dests->DestHops(destNo));

	for (j=0; j<dests->DestHops(destNo); j++) {
	    struct in_addr router;
	    float lat;
	    int retTtl;
	    int numProbes;
            long sendtime;
	    if (!dests->HopStatus(destNo, j, &router, &lat, &retTtl, &numProbes, &sendtime)) {
		router.s_addr = 0;
		lat = 0;
		retTtl = 0;
	    }
            fprintf(outfp, "H %d %s %f %d %ld\n", j, inet_ntoa(router), lat, retTtl, sendtime);
	}
	fflush(outfp);
    }

    fclose(outfp); outfp = NULL;

    FILE *cntfile = fopen(countFile, "w");
    countRecords += size;
    fprintf(cntfile, "%d\n", countRecords);
    fclose(cntfile);

    if(pfindRateLimitHops != NULL)
    (*pfindRateLimitHops)(dests, tracedCopy, size);
}

void findRateLimitHops(DestList *dests, int tracedCopy[], int size)
{
    int i, j;
    int len;

    for (i=0; i<size; i++) {
	//struct in_addr ip;
	int destNo = tracedCopy[i];
	//inet_aton(dests->GetDestName(destNo), &ip);
	//fprintf(outfp, "D %s n %d\n", inet_ntoa(ip), dests->DestHops(destNo));

	for (j=0; j<dests->DestHops(destNo); j++) {
	    struct in_addr router;
	    float lat;
	    int retTtl;
	    int numProbes;
            long sendtime;
	    if (!dests->HopStatus(destNo, j, &router, &lat, &retTtl, &numProbes, &sendtime))
                continue;

            ttl_count[j][router.s_addr]++;
            //fprintf(outfp, "H %d %s %f %d %ld\n", j, inet_ntoa(router), lat, retTtl, sendtime);
	}
    }
}



void RecordDestDone(DestList *dests, int destNo)
{
    dests->MarkDone(destNo);
    tracedDests[numTraced] = destNo;
    numTraced++;
    if (numTraced == BLOCK) {
	int tracedCopy[BLOCK];
	for (int i=0; i<BLOCK; i++)
	    tracedCopy[i] = tracedDests[i];
	numTraced = 0;
	CommunicateResultsText(dests, tracedCopy, BLOCK);
    }
}

void STSingleHopProbe(DestList *dests, int destNo, struct ConnState c,
		    int seq, ProbePool *pool)
{
    char *destName = dests->GetDestName(destNo);
    struct in_addr ip;
    inet_aton(destName, &ip);
    int i, j;
    int fails = 0;
    int nProbes;
    int hops;
    int retTtl;
    struct in_addr a;
    a.s_addr = 0;
printf("single hop probe\n"); //XXX: kvbp
    hops = dests->DestHops(destNo);

    if (hops > 0) {
	struct in_addr addr;
	float lat;
        long sendtime;
        struct timeval ts;
	int status = dests->HopStatus(destNo, hops-1, &addr, &lat, &retTtl, &nProbes, &sendtime);
        ts.tv_sec = sendtime; ts.tv_usec = 0;
	if ((aggressive && (status == 0) && (nProbes < MAX_QUERIES))
	    || (!aggressive && (nProbes < MAX_QUERIES)))
	{
	    /* start a query for current hop */
	    struct timeval todTime, pcapTime;
	    SendSingleProbe(c.sndSock, c.srcAddr, ip.s_addr, c.outPkt,
			    hops, (seq << 8) + (hops << 3) + nProbes, &todTime, &pcapTime, c.handle);
	    dests->SetHopInfo(destNo, hops - 1, status, addr, lat, retTtl, nProbes + 1, &ts);
	    if (pcapTime.tv_sec > 0 || pcapTime.tv_usec > 0) {
		pool->SetTimeStamp(seq, pcapTime);
	    } else {
		pool->SetTimeStamp(seq, todTime);
	    }
	    return;
	}
#ifdef PRINT
	else if (status == 0)
	    printf("%s %d *\n", dests->GetDestName(destNo), hops);
#endif
    }

    if (FinishProbing(dests->GetDest(destNo))) {
#ifdef PRINT
	printf("done: %s in %d\n", dests->GetDestName(destNo), hops);
#endif
	dests->UpdateDestStats(destNo);
	pool->MarkDone(seq);
	RecordDestDone(dests, destNo);	
	destNo = GetNextRandomDest(dests, pool);
	if (destNo != -1)
	    seq = pool->AddToPool(destNo);
	hops = 0;
    }
    if (destNo != -1) {
	/* start a query for next hop */
	struct timeval todTime, pcapTime;
	SendSingleProbe(c.sndSock, c.srcAddr, ip.s_addr, c.outPkt,
			hops + 1, (seq << 8) + ((hops + 1) << 3) + 0, &todTime, &pcapTime, c.handle);
	dests->SetHopInfo(destNo, hops, 0, a, 0, 1, NULL);
	if (pcapTime.tv_sec > 0 || pcapTime.tv_usec > 0)	
	    pool->SetTimeStamp(seq, pcapTime);
	else
	    pool->SetTimeStamp(seq, todTime);
    }
}


void ReceiveLoop(DestList *dests, struct ConnState c, ProbePool *pool)
{
    char packet[1600];
    struct sockaddr_in from;

int probesent = 0; //XXX: kvbp
    while (!pool->Empty()) {
	int rcvSeq, seqId, nextSeq = -1, retTtl;

	struct timeval timeCheck;
	gettimeofday(&timeCheck, NULL);
	if (timeCheck.tv_sec > finishTime + 10) {
	    printf("killing process\n");
	    exit(0);
	}

	struct timeval t1, t2, wait;
	bzero(packet, 512);
	t1 = pool->GetMinTimeStamp();
	//wait.tv_sec = t1.tv_sec + WAITTIME;
	//wait.tv_usec = t1.tv_usec;
	wait.tv_sec = t1.tv_sec + ((probesent) ? WAITTIME : 0); //XXX: kvbp
	wait.tv_usec = t1.tv_usec + ((probesent) ? 0 : 1000); //XXX: kvbp
gettimeofday(&t2, NULL); printf("receive packet.. sent=%d t1: %ld cur: %ld wait: %ld ", probesent, t1.tv_sec, t2.tv_sec, wait.tv_sec); //XXX: kvbp
	int retVal = ReceivePacket(c.rcvSock, &from, &wait, &t2, packet,
				   &seqId, &retTtl, NULL);
	int hop;

	rcvSeq = (seqId >> 8) & 0xFF;
	if (retVal != 0) {
	    struct in_addr ipAddr;
	    int destNo = pool->GetItem(rcvSeq);
	    struct ip *ip = (struct ip *)packet;
	    int hlen = ip->ip_hl << 2;
	    struct icmp *icp = (struct icmp *)(packet + hlen);
	    struct ip *hip = &icp->icmp_ip;

#if 0 /* really bad bug!!!! */
	    if (destNo != -1) {
		char *destName = dests->GetDestName(destNo);
		struct in_addr ip;
		inet_aton(destName, &ip);
		if (from.sin_addr.s_addr != ip.s_addr)
		    destNo = -1;
		printf("got here %s %s\n", inet_ntoa(from.sin_addr), destName);
	    }
#endif
	    struct in_addr dstIP;

	    if (destNo != -1)
		dstIP = dests->GetDest(destNo)->ip;
	    
	    if (destNo == -1)
		retVal = 0;
	    else if ((from.sin_addr.s_addr == dstIP.s_addr) ||
		     (hip->ip_dst.s_addr == dstIP.s_addr)) {
		hop = dests->DestHops(destNo) - 1;
		float oldLat;
		int np;
		int status = dests->HopStatus(destNo, hop, NULL, &oldLat, NULL, &np, NULL);
printf("received %d hop %d status %d latency %f\n\n", destNo, hop, status, deltaT(&t1, &t2)); //XXX: kvbp
		if (((seqId & 0xFF) != ((hop + 1) << 3)) ||
		    ((seqId & 0x7) != np - 1)) {
		    retVal = 0;
		}
		else {
		    ipAddr = from.sin_addr;
		    t1 = pool->GetTimeStamp(rcvSeq);
		    float currCost = deltaT(&t1, &t2);
#if 0
		    if (oldLat > 0 && oldLat < currCost)
			currCost = oldLat;
#endif
		    if (oldLat == 0 || oldLat > currCost)
			dests->SetHopInfo(destNo, hop, 1, ipAddr, currCost, retTtl, np, &t1);

		    if (recordroute) {
			if (retVal == -2) {
			    char *offset = (char *)packet + 24;
			    printf("fields: %d\n", (int)packet[23]);
			    for (int k=0; k<9; k++) {
				struct in_addr ip;
				memcpy(&ip, offset+k*sizeof(int), sizeof(int));
				printf("%s\n", inet_ntoa(ip));
			    }
			} else if (retVal == -1) {
			    register struct ip *ip = (struct ip *)packet;
			    int hlen = ip->ip_hl << 2;
			    register struct icmp *icp = (struct icmp *)(packet + hlen);
			    register struct ip *hip;

			    hip = &icp->icmp_ip;
			    hlen = hip->ip_hl << 2;

			    char *offset = (char *)hip + 24;
			    printf("fields: %d\n", (int)((char *)hip)[23]);
			    for (int k=0; k<9; k++) {
				struct in_addr ip;				
				memcpy(&ip, offset+k*sizeof(int), sizeof(int));
				printf("%s\n", inet_ntoa(ip));
			    }
			}
		    }
#ifdef PRINT
		    printf("%s %d %s %f %d %d\n", dests->GetDestName(destNo), hop + 1,
			   inet_ntoa(from.sin_addr), deltaT(&t1, &t2), retTtl,
			   ((struct ip *)packet)->ip_ttl);
#endif
		}
	    }
	}
	if (retVal == -2 || retVal > 0) {
	    int destNo = pool->GetItem(rcvSeq);
#ifdef PRINT
	    printf("done: %s in %d\n", dests->GetDestName(destNo), hop);
#endif
	    dests->UpdateDestStats(destNo);
	    pool->MarkDone(rcvSeq);
	    RecordDestDone(dests, destNo);

	    destNo = GetNextRandomDest(dests, pool);
	    if (destNo != -1)
		nextSeq = pool->AddToPool(destNo);
	    else
		nextSeq = -1;
	} 
	else if (retVal == -1) {
	    nextSeq = rcvSeq;
	}

	if (nextSeq == -1)
	    nextSeq = pool->CheckExpired(WAITTIME);
printf("pre-not expired: %d\n", nextSeq);
probesent = 0; //XXX: kvbp
	while (nextSeq != -1) {
printf("not expired: %d\n", nextSeq);
	    int destNo = pool->GetItem(nextSeq);
	    STSingleHopProbe(dests, destNo, c, nextSeq, pool);
	    nextSeq = pool->CheckExpired(WAITTIME);
probesent = 1; //XXX: kvbp
	}
    }
}

//XXX/TODO: add start-TTL config; add config to mobstor file
void *Prober(DestList *dests, struct ConnState c, int probers)
{
    ProbePool *pool = new ProbePool(probers);
    struct timeval tv;

    gettimeofday(&tv, NULL);
    finishTime = 40*dests->NumDests()/probers;
    finishTime = tv.tv_sec + (finishTime < 200 ? 200 : finishTime);
    while (1) {
	int destNo = GetNextRandomDest(dests, pool);
	if (destNo == -1)
	    break;
	int seq = pool->AddToPool(destNo);
	STSingleHopProbe(dests, destNo, c, seq, pool);
	if (pool->Full())
	    break;
    }
    ReceiveLoop(dests, c, pool);
    CommunicateResultsText(dests, tracedDests, numTraced);

    delete pool;
}


#if 0
void PrintArtsFile(char *src, DestList *dests, char *fileName)
{
    ofstream *out = new ofstream(fileName,ios::out|ios::trunc);
    /* error check */
    if (!out || !(*out)) {
	cerr << "unable to open '" << fileName << "' as output file: "
	     << strerror(errno) << endl;
	exit(1);
    }

    for (int i=0; i<dests->NumDests(); i++) {
	Destination *d = dests->GetDest(i);
	ipv4addr_t srcIp = inet_addr(src);
	ipv4addr_t dstIp = inet_addr(dests->GetDestName(i));
	ArtsIpPathData *pData = new ArtsIpPathData(srcIp, dstIp);

	for (int h=0; h<dests->DestHops(i); h++) {
	    struct in_addr addr;
	    float lat;
	    int numProbes;
	    int state = dests->HopStatus(i, h, &addr, &lat, NULL, &numProbes);
	    if (state) {
		struct timeval t;
		t.tv_sec = (int)lat;
		t.tv_usec = (int)((lat - (int)lat)*1000000);
		pData->AddHop(addr.s_addr, h, t, numProbes);
	    } else {
		struct timeval t = {0, 0};
		pData->AddHop(0, h, t, MAX_QUERIES);
	    }
	}
	pData->write(*out);
	printf("wrote\n");
	delete pData;
    }
    out->close();
}
#endif

void ReadOldinfo(DestList *dests)
{
    FILE *fp = fopen(countFile, "r");
    if (fp == NULL) {
	//char cmd[100];
	//sprintf(cmd, "rm -f %s", traceFile);
	//system(cmd);
	return;
    }
    char line[MAX_LINE_SIZE];
    char *res = fgets(line, MAX_LINE_SIZE, fp);
    int num = 0;
    fclose(fp);

    if (res == NULL)
	return;
    if (sscanf(res, "%d", &num) != 1)
	return;
    if (num > 0 && num < dests->NumDests()) {
	nextDest = (num - 1000 < 0 ? 0 : num - 1000);
	countRecords = (num - 1000 < 0 ? 0 : num - 1000);
    }
    if (countRecords == 0) {
	//char cmd[100];
	//sprintf(cmd, "rm -f %s", traceFile);
	//system(cmd);
	return;
    }
}


main(int argc, char **argv)
{
    FILE *fp;
    int probers;
    pfindRateLimitHops = NULL;

#ifndef STOP_EARLY
    if (argc != 5 && argc != 7) {
	fprintf(stderr, "usage: randstprober numprobers probelist device aggressive\n");
	exit(1);
    }

    if (argc == 7) {
	traceFile = argv[5];
	countFile = argv[6];
    } else {
	traceFile = strdup("trace.out");
	countFile = strdup("count.out");
    }
#else
    if (argc != 7 && argc != 9) {
	fprintf(stderr, "usage: randstprober numprobers probelist device aggressive bgporigins aliasmap\n");
	exit(1);
    }

    if (argc == 9) {
	traceFile = argv[7];
	countFile = argv[8];
    } else {
	traceFile = strdup("trace.out");
	countFile = strdup("count.out");
    }

    ReadAsMapping(argv[5]);
    ReadAliasFile(argv[6]);
#endif

    useicmp = 1;
    
    sscanf(argv[1], "%d", &probers);
    sscanf(argv[4], "%d", &aggressive);
    
    struct ConnState c = InitConnection(argv[3]);

    for(int iter = 0; iter < 30; iter++)
    {
	    printf("iteration %d\n", iter);
	    fp = fopen(argv[2], "r");
	    assert(fp != NULL);
	    DestList *dests = new DestList(1500000);

            if(iter % 2 == 0) //XXX: kvbp
	    {
		    ReadIPList(fp, dests, 1000);
		    pfindRateLimitHops = findRateLimitHops;
		    probers = 1;
	    }
            else
	    {
		    ReadIPList(fp, dests, 1500000);
		    pfindRateLimitHops = NULL;
		    sscanf(argv[1], "%d", &probers);
	    }

#ifdef STOP_EARLY
	    for (int i=0; i<dests->NumDests(); i++) {
		    Destination *d = dests->GetDest(i);
		    d->destAs = LookupAS(d->ip);
	    }
#else
	    for (int i=0; i<dests->NumDests(); i++) {
		    Destination *d = dests->GetDest(i);
		    d->destAs = -1;
	    }
#endif

	    ReadOldinfo(dests);
	    Prober(dests, c, probers);

	    if(iter % 2 == 0) //XXX: kvbp
	    {
                for(int j=0; j < 256; j++)
                {
                    printf("hop-%d: ", j);
                    std::map <uint32_t, int> t = ttl_count[j];
		    if(t.size() > 4) break;
                    for(std::map<uint32_t, int>::iterator iter(t.begin()); iter != t.end(); iter++)
                    {
                        struct in_addr router; router.s_addr = iter->first;
                        printf("%s:%d ", inet_ntoa(router), iter->second);
                    }
                    printf("\n");
                }
	    }

	    nextDest = numTraced = countRecords = 0;

	    delete dests;
	    fclose(fp);
	    system("rm -f .tmp_*");

            sleep(60);
    }

    free(c.outPkt);
    if(useicmp) pcap_close(c.handle);
    close(c.sndSock);
    close(c.rcvSock);
}

