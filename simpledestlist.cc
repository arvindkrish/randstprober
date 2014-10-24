#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "proberoute.h"

void InitSimpleDest(SimpleDest *d, char *c, int ttl, char *rtr, float spacing)
{
    d->name = strdup(c);
    inet_aton(c, &d->destAddr);
    inet_aton(rtr, &d->routerAddr);
    d->ttl = ttl;
    d->spacing = spacing;
    d->traced = 0;
    d->state = 0;
    d->numProbes = 0;
    d->usefulProbes = 0;
    for (int i=0; i<6; i++)
	d->counts[i] = 0;

    d->smallRtt = 0;
    d->smallRttAvg = 0;
    d->numSmall = 0;

    d->largeRtt = 0;
    d->largeRttAvg = 0;
    d->numLarge = 0;
    d->numFirst = 0;
    
    d->gap = 0;
    d->minGap = 1000;
    d->numGaps = 0;

    for (int i=0; i<NUM_SIZES; i++) {
	d->bwRtts[i] = 0;
	d->replies[i] = 0;
    }
    d->sizePhase = 0;
    d->seqState = 0;
}

SimpleDestList::SimpleDestList(int num) {
    maxDests = num;
    numDests = 0;
    dests = new SimpleDest[num];
    nextProbe = 0;
    numDone = 0;
}
    
int SimpleDestList::InitNextDest(char *c, int ttl, char *rtr)
{
    int tmp;
    assert(numDests < maxDests);
    InitSimpleDest(&dests[numDests], c, ttl, rtr, 0.5);
    tmp = numDests;
    numDests++;
    return tmp;
}

int SimpleDestList::InitNextDest(char *c, int ttl, char *rtr, float spacing)
{
    int tmp;
    assert(numDests < maxDests);
    InitSimpleDest(&dests[numDests], c, ttl, rtr, spacing);
    tmp = numDests;
    numDests++;
    return tmp;
}



