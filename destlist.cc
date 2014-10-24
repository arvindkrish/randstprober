#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "proberoute.h"

unsigned int ReverseAddr(unsigned int addr)
{
    return ((addr & 0xff) << 24) + ((addr & 0xff00) << 8)
	+ ((addr & 0xff0000) >> 8) + ((addr & 0xff000000) >> 24);
}

/* convert MSB as MS IP address to a string */
char *my_inet_ntoa(unsigned int addr)
{
    struct in_addr ip;
    ip.s_addr = ReverseAddr(addr);
    return inet_ntoa(ip);
}

/* convert string to a number -- but the number is MSB as MS */
unsigned int my_inet_aton(char *name)
{
    struct in_addr ip;
    inet_aton(name, &ip);
    return ReverseAddr(ip.s_addr);
}

#include "util.h"

void InitDestination(Destination *d, char *c, int size)
{
    d->name = strdup(c);
    inet_aton(d->name, &d->ip);
    d->numHops = 0;
    d->numHops = 0;
    d->maxHops = 5;
    d->traced = 0;
    d->ttllimit = MAX_HOPS;
    d->size = size;
    d->hops = new HopInfo[5];
    for (int i=0; i<5; i++) {
	d->hops[i].state = 0;
	d->hops[i].numProbes = 0;
	d->hops[i].retTtl = 0;
    }
}

DestList::DestList(int num) {
    maxDests = num;
    numDests = 0;
    dests = new Destination[num];
    nextProbe = 0;
    numDone = 0;
}
    
int DestList::InitNextDest(char *c)
{
    int tmp;
    assert(numDests < maxDests);
    InitDestination(&dests[numDests], c, 1);
    tmp = numDests;
    numDests++;
    return tmp;
}

int DestList::InitNextDest(char *c, int size)
{
    int tmp;    
    assert(numDests < maxDests);
    InitDestination(&dests[numDests], c, size);
    tmp = numDests;
    numDests++;
    return tmp;
}

DestList::~DestList()
{
    for(int c = 0; c < numDests; c++)
    {
        Destination *d = &dests[c];
        free(d->name);
        delete [] d->hops;
    }
    delete [] dests;
}

void SetDestHopInfo(Destination *d, int n, int reachable,
		    struct in_addr a, float l, int retTtl, 
                    int nP, struct timeval *sendtime)
{
    if (n >= d->maxHops) {
	HopInfo *t = new HopInfo[n + 5];
	bcopy(d->hops, t, d->maxHops*sizeof(HopInfo));
	delete [] d->hops;
	d->hops = t;
	d->maxHops = n + 5;
    }
    d->hops[n].state = reachable;
    d->hops[n].addr = a;
    d->hops[n].latency = l;
    d->hops[n].retTtl = retTtl;
    d->hops[n].numProbes = nP;
    if (d->numHops < n+1)
	d->numHops = n+1;
    d->hops[n].sendtime = (sendtime) ? sendtime->tv_sec : 0;
}
   
void DestList::SetHopInfo(int d, int n, int reachable,
			  struct in_addr a, float l)
{
    assert(d < numDests);
    SetDestHopInfo(&dests[d], n, reachable, a, l, 0, 0, NULL);
}

void DestList::SetHopInfo(int d, int n, int reachable,
			  struct in_addr a, float l, int nProbes, 
			  struct timeval *sendtime)
{
    assert(d < numDests);
    SetDestHopInfo(&dests[d], n, reachable, a, l, 0, nProbes, sendtime);
}

void DestList::SetHopInfo(int d, int n, int reachable,
			  struct in_addr a, float l, int retTtl, int nProbes, struct timeval *sendtime)
{
    assert(d < numDests);
    SetDestHopInfo(&dests[d], n, reachable, a, l, retTtl, nProbes, sendtime);
}

void DestList::PrintDestInfo(int d, char const *prefixString)
{
    Destination targ = dests[d];
    printf("%s %s ", prefixString, targ.name);
    for (int i=0; i<targ.numHops; i++) {
	if (targ.hops[i].state)
	    printf("%s %f %d ", inet_ntoa(targ.hops[i].addr),
		   targ.hops[i].latency, targ.hops[i].retTtl);
	else
	    printf("* ");
    }
    printf("\n");
}

void DestList::PrintAllDests(char *prefixString)
{
    for (int i=0; i<numDests; i++)
	PrintDestInfo(i, prefixString);
}

void DestList::PrintAllDests()
{
    for (int i=0; i<numDests; i++)
	PrintDestInfo(i, "local");
}

void DestList::PrintAllDataBinary(char *fname)
{
    FILE *fp = fopen(fname, "w");
    fwrite(&numDests, sizeof(int), 1, fp);
    for (int d=0; d<numDests; d++) {
	Destination targ = dests[d];
	struct { int ip, numHops; } ipRec;
	struct in_addr addr;
	inet_aton(targ.name, &addr);
	ipRec.ip = addr.s_addr;
	ipRec.numHops = targ.numHops;
	fwrite(&ipRec, sizeof(ipRec), 1, fp);
	for (int i=0; i<targ.numHops; i++) {
	    struct { int ip; float lat; } routerRec;
	    if (targ.hops[i].state) {
		routerRec.ip = targ.hops[i].addr.s_addr;
		routerRec.lat = targ.hops[i].latency;
	    } else {
		routerRec.ip = 0;
		routerRec.lat = 0;
	    }
	    fwrite(&routerRec, sizeof(routerRec), 1, fp);
	}
    }
    fclose(fp);
}

void DestList::PrintUpto(int limit)
{
    int d;
    fpout = fopen(foutName, "a");
    assert(fpout != NULL);
    for (d=nextPrint; d<limit; d++) {
	if (dests[d].traced == 0)
	    break;
	
	Destination targ = dests[d];
	struct { int ip, numHops; } ipRec;
	struct in_addr addr;
	inet_aton(targ.name, &addr);
	ipRec.ip = addr.s_addr;
	ipRec.numHops = targ.numHops;
	fwrite(&ipRec, sizeof(ipRec), 1, fpout);
	for (int i=0; i<targ.numHops; i++) {
	    struct { int ip; float lat; } routerRec;
	    if (targ.hops[i].state) {
		routerRec.ip = targ.hops[i].addr.s_addr;
		routerRec.lat = targ.hops[i].latency;
	    } else {
		routerRec.ip = 0;
		routerRec.lat = 0;
	    }
	    fwrite(&routerRec, sizeof(routerRec), 1, fpout);
	}
    }
    nextPrint = d;
    assert(fflush(fpout) == 0);
    sync();
    assert(fclose(fpout) == 0);
#if 0
    if (nextPrint == numDests)
	fclose(fpout);
    else
	fflush(fpout);
#endif
}

void DestList::LoadData(char *fname)
{
    FILE *fp = fopen(fname, "r");
    int num;
    fread(&num, sizeof(int), 1, fp);
    numDests = num;
    if (numDests > maxDests) {
	delete dests;
	dests = new Destination[numDests];
    }
    for (int i=0; i<num; i++) {
	struct { int ip, numHops; } ipRec;
	fread(&ipRec, sizeof(ipRec), 1, fp);
	struct in_addr addr;
	addr.s_addr = ipRec.ip;
	dests[i].name = strdup(inet_ntoa(addr));
	dests[i].maxHops = ipRec.numHops + 2;
	dests[i].numHops = ipRec.numHops;
	dests[i].hops = new HopInfo[ipRec.numHops + 2];
	for (int j=0; j<ipRec.numHops; j++) {
	    struct { int ip; float lat; } routerRec;
	    fread(&routerRec, sizeof(routerRec), 1, fp);
	    if (routerRec.ip == 0)
		dests[i].hops[j].state = 0;
	    else {
		dests[i].hops[j].state = 1;		    
		dests[i].hops[j].addr.s_addr = routerRec.ip;
		dests[i].hops[j].latency = routerRec.lat;
	    }		    
	}
    }
    printf("%s %d\n", dests[num-1].name, dests[num-1].numHops);
}
    
int DestList::GetNextDest()
{
    int temp = nextProbe;
    nextProbe++;
    return temp;
}

void DestList::UpdateDestStats(int destNo)
{
    numDone++;
    MarkDone(destNo);
}
    
void DestList::WaitAndPrint()
{
    PrintUpto(NumTraced());
}

int DestList::HopStatus(int d, int hop, struct in_addr *addr,
			float *lat, int *retTtl, int *numprobes, 
                        long *ts)
{
    assert (d < numDests);
    if (hop >= dests[d].numHops)
	return -1;

    if (addr)
	*addr = dests[d].hops[hop].addr;

    if (lat)
	*lat = dests[d].hops[hop].latency;

    if (retTtl)
	*retTtl = dests[d].hops[hop].retTtl;

    if (numprobes)
	*numprobes = dests[d].hops[hop].numProbes;

    if(ts)
        *ts = dests[d].hops[hop].sendtime;
    
    return dests[d].hops[hop].state;
}

int DestList::DestHops(int d)
{
    assert (d < numDests);
    return dests[d].numHops;
}

