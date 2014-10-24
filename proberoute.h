#ifndef _PROBEROUTE_H
#define _PROBEROUTE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "tracer.h"

typedef struct {
    struct in_addr addr;
    float latency;
    int retTtl;
    int state;		/* 0 for no reply, 1 for success */
    int numProbes;
    long sendtime;
} HopInfo;

typedef struct {
    char *name;
    struct in_addr ip;
    int maxHops;
    int numHops;
    HopInfo *hops;
    int traced;
    int size;		/* only for prefixes */
    int destAs;
    int ttllimit;
    float curr;
} Destination;

#define PROBES_PER_SIZE 40
#define NUM_SIZES 10
#define START_SIZE 0
#define SIZE_INCREMENT 100

typedef struct {
    char *name;
    struct in_addr destAddr;
    struct in_addr routerAddr;
    int ttl;
    float spacing;
    
    int traced;

    int numProbes;
    int usefulProbes;

    int counts[8];

    float smallRtt;
    float smallRttAvg;
    int numSmall;
    
    float largeRtt;
    float largeRttAvg;
    int numLarge;
    int numFirst;

    struct timeval recv1, recv2;
    float gap;
    float inGap;
    float minGap;
    int numGaps;

    struct timeval t1, t2, t3;
    int state;		

    float bwRtts[NUM_SIZES];
    int replies[NUM_SIZES];
    int sizePhase;
    int seqState;
} SimpleDest;

void SetDestHopInfo(Destination *, int, int, struct in_addr, float, int, int, struct timeval *);
void InitDestination(Destination *d, char *c, int size);
char *my_inet_ntoa(unsigned int addr);
unsigned int my_inet_aton(char *name);

class SimpleDestList {
 public:
    SimpleDestList(int num);
    int InitNextDest(char *c, int ttl, char *rtr);
    int InitNextDest(char *c, int ttl, char *rtr, float spacing);

    SimpleDest *GetDest(int d) {
	assert(d < numDests);
	return dests + d;
    }

    char *GetDestName(int d) {
	assert(d < numDests);
	return dests[d].name;
    }

    void MarkDone(int destNo) { dests[destNo].traced = 1; }
    void MarkUndone(int destNo) { dests[destNo].traced = 0; }
    int DoneStatus(int destNo) { return dests[destNo].traced; }

    int NumDests() { return numDests; }

    int GetNextDest() {
	int temp = nextProbe;
	nextProbe++;
	return temp;
    }

    int GetDestState(int destNo) { return dests[destNo].state; }
    void SetDestState(int destNo, int state) { dests[destNo].state = state; }

    void SetSmallRtt(int destNo, float rtt) {
	if (dests[destNo].smallRtt == 0)
	    dests[destNo].smallRtt = rtt;
	if (rtt < dests[destNo].smallRtt)
	    dests[destNo].smallRtt = rtt;
    }

    void SetLargeRtt(int destNo, float rtt) {
	if (dests[destNo].largeRtt == 0)
	    dests[destNo].largeRtt = rtt;
	if (rtt < dests[destNo].largeRtt)
	    dests[destNo].largeRtt = rtt;
    }

    void SetGap(int destNo, int g) {
	int num = dests[destNo].numGaps;
	dests[destNo].gap = (num*dests[destNo].gap + g)/(num + 1);
	dests[destNo].numGaps = num + 1;
    }
    
 private:
    SimpleDest *dests;
    int numDests;
    int maxDests;

    int nextProbe;
    int numDone;

};

class DestList {

 public:
    DestList(int num);
    
    int InitNextDest(char *c);
    
    int InitNextDest(char *c, int size);

    Destination *GetDest(int d) {
	assert(d < numDests);
	return dests + d;
    }
    
    char *GetDestName(int d) {
	assert(d < numDests);
	return dests[d].name;
    }

    int GetDestSize(int d) {
	assert(d < numDests);
	return dests[d].size;
    }
    
    void SetHopInfo(int d, int n, int reachable, struct in_addr a, float l);
    void SetHopInfo(int d, int n, int reachable, struct in_addr a, float l, int nP, struct timeval *ts);
    void SetHopInfo(int d, int n, int reachable, struct in_addr a, float l, int retTtl, int nP, struct timeval *ts);
    
    void PrintDestInfo(int d, char const *prefix);
    
    void PrintAllDests(char *prefix); 
    void PrintAllDests(); 

    void PrintAllDataBinary(char *fname);

    void LoadData(char *fname);
    
    int NumDests() { return numDests; }

    int GetNextDest();

    int HopStatus(int d, int hop, struct in_addr *addr, float *lat, int *retTtl, int *np, long *ts);

    int DestHops(int d);
    
    void UpdateDestStats(int destNo);
    
    void MarkDone(int destNo) { dests[destNo].traced = 1; }
    void MarkUndone(int destNo) { dests[destNo].traced = 0; }
    int DoneStatus(int destNo) { return dests[destNo].traced; }
    
    int DestTracedP(int destNo) { return dests[destNo].traced; }

    void StartPrintBinary(char *fname) {
	fpout = fopen(fname, "w");
	foutName = fname;
	fwrite(&numDests, sizeof(int), 1, fpout);
	fclose(fpout);
	nextPrint = 0;
    }

    void PrintUpto(int limit);

    int NumTraced() { return numDone; }

    void WaitAndPrint();

    ~DestList();

 private:
    Destination *dests;
    int numDests;
    int maxDests;

    int nextProbe;
    int numDone;
    char *foutName;
    FILE *fpout;
    int nextPrint;
};

class ProbePool {
#define PR_POOL_MAX_PROBES 1000
 public:
    ProbePool(int max) {
	assert (max <= PR_POOL_MAX_PROBES);
	for (int i=0; i<max; i++)
	    probes[i].used = 0;
	maxActive = max;
	numActive = 0;
    }
    
    void MarkDone(int num) {
	probes[num].used = 0;
	numActive--;
    }
    
    int Full() {
	return (numActive >= maxActive);
    }

    int Empty() {
	return (numActive == 0);
    }

    int AlreadyInPool(int item) {
	int i;
	for (i=0; i<maxActive; i++) {
	    if (probes[i].used) {
		if (probes[i].destNo == item)
		    return 1;
	    }
	}
	return 0;
    }
    
    int AddToPool(int item) {
	int i;
	assert (numActive < maxActive);
	for (i=0; i<maxActive; i++)
	    if (!probes[i].used) {
		probes[i].destNo = item;
		struct timeval t;
		gettimeofday(&t, NULL);
		probes[i].tStamp = t;
		probes[i].used = 1;
		break;
	    }
	numActive++;
	return i;
    }

    int GetItem(int num) {
	if (num < maxActive && probes[num].used == 1)
	    return probes[num].destNo;
	else
	    return -1;
    }

    struct timeval GetTimeStamp(int num) {
	assert (num < maxActive && probes[num].used == 1);
	return probes[num].tStamp;
    }

    struct timeval GetMinTimeStamp() {
	struct timeval min;
	gettimeofday(&min, NULL);
	for (int i=0; i<maxActive; i++) {
	    if (!probes[i].used)
		continue;
	    struct timeval t = probes[i].tStamp;
	    if (t.tv_sec < min.tv_sec ||
		((t.tv_sec == min.tv_sec) && (t.tv_usec < min.tv_usec)))
		min = t;
	}
	return min;
    }
    
    void SetTimeStamp(int num, struct timeval t) {
	assert (num < maxActive && probes[num].used == 1);
	probes[num].tStamp = t;
    }

    int CheckExpired(float waitf) {
	struct timeval curr;
	struct timeval waittime;
	waittime.tv_sec = (int)waitf;
	waittime.tv_usec = (int)((waitf - (int)waitf)*1000000);
	gettimeofday(&curr, NULL);
	tvsub(&curr, &waittime);
	/* curr.tv_sec -= wait; */
	for (int i=0; i<maxActive; i++) {
	    if (!probes[i].used)
		continue;
	    struct timeval t = probes[i].tStamp;
	    if (t.tv_sec < curr.tv_sec ||
		((t.tv_sec == curr.tv_sec) && (t.tv_usec < curr.tv_usec)))
		return i;
	}
	return -1;
    }

    int CheckExpiredTime(struct timeval curr) {
	for (int i=0; i<maxActive; i++) {
	    if (!probes[i].used)
		continue;
	    struct timeval t = probes[i].tStamp;
	    if (t.tv_sec < curr.tv_sec ||
		((t.tv_sec == curr.tv_sec) && (t.tv_usec < curr.tv_usec)))
		return i;
	}
	return -1;
    }
    
 private:
    struct ProbeInfo {
	int destNo;
	struct timeval tStamp;
	int used;
    } probes[PR_POOL_MAX_PROBES];
#if 0
    int *activeProbes;
    struct timeval *tStamps;
    int *used;
#endif
    int numActive;
    int maxActive;
};

#endif
