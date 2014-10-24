#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include "proberoute.h"
#include "util.h"


void ReadIPList(FILE *fp, DestList *dests, int maxDests)
{
    char *res;
#define MAX_LINE_SIZE 250
    char line[MAX_LINE_SIZE];
    int num = 0;

    res = fgets(line, MAX_LINE_SIZE, fp);
    while (res) {
	char ipAddr[40];
	int ttl;
	int retVal = sscanf(line, "%s %d", ipAddr, &ttl);
	int dnum = dests->InitNextDest(ipAddr);
	if (retVal == 2 && ttl > 0 && ttl < MAX_HOPS) {
	    dests->GetDest(dnum)->ttllimit = MAX_HOPS;
	}
	res = fgets(line, MAX_LINE_SIZE, fp);
	num++;
	if(num >= maxDests) break;
    }
    printf("loaded %d %s\n", num, dests->GetDestName(num-1));
}

void ReadSimpleIPList(FILE *fp, SimpleDestList *dests, int maxDests)
{
    char *res;
#define MAX_LINE_SIZE 250
    char line[MAX_LINE_SIZE];
    int num = 0;

    res = fgets(line, MAX_LINE_SIZE, fp);
    while (res) {
	char ipAddr[40];
	char routerAddr[40];
	int ttl;
	int retVal = sscanf(line, "%s %d %s", ipAddr, &ttl, routerAddr);
	if (retVal == 1) {
	    ttl = 40;
	    strcpy(routerAddr, ipAddr);
	} else if (retVal == 2) {
	    strcpy(routerAddr, ipAddr);
	}
	dests->InitNextDest(ipAddr, ttl, routerAddr);
	res = fgets(line, MAX_LINE_SIZE, fp);
	num++;
	assert(num < maxDests);
    }
    /*    printf("loaded %d %s\n", num, dests->GetDestName(num-1)); */
}

void ReadABIPList(FILE *fp, SimpleDestList *dests, int maxDests)
{
    char *res;
#define MAX_LINE_SIZE 250
    char line[MAX_LINE_SIZE];
    int num = 0;

    res = fgets(line, MAX_LINE_SIZE, fp);
    while (res) {
	char ipAddr[40];
	float spacing;
	int ttl;
	if (sscanf(line, "%s %d %f", ipAddr, &ttl, &spacing) == 1) {
	    ttl = 40;
	    spacing = 0.1;
	}
	dests->InitNextDest(ipAddr, ttl, ipAddr, spacing);
	res = fgets(line, MAX_LINE_SIZE, fp);
	num++;
	assert(num < maxDests);
    }
    /*    printf("loaded %d %s\n", num, dests->GetDestName(num-1)); */
}

void ReadIPPrefix(FILE *fp, DestList *dests)
{
    char *res;
#define MAX_LINE_SIZE 250
    char line[MAX_LINE_SIZE];
    int num = 0;
    int len;
    unsigned int temp;

    res = fgets(line, MAX_LINE_SIZE, fp);
    while (res) {
	char tmpstr[MAX_LINE_SIZE];
	sscanf(line, "%s %d", tmpstr, &len);
	temp = my_inet_aton(tmpstr);
	temp = temp + 1;
	dests->InitNextDest(my_inet_ntoa(temp), 1 << (32 - len));
	res = fgets(line, MAX_LINE_SIZE, fp);
	num++;
    }
    printf("loaded %d %x %d\n", num, temp, len);
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
	pData->write(*out, 1, 0);
	printf("wrote\n");
	delete pData;
    }
    out->close();
}
#endif

void SendSingleProbe(Destination *dest, int destNo)
{
    char *destName = dest->name;
    char cmdString[100];
    int nqueries = 0;
    int fails = 0;

    for (int i=1; i<=30; ) {
	char fname[30];
	sprintf(fname, ".tmp_%d", destNo);
	sprintf(cmdString, "traceroute -n -I -f %d -m %d -q 1 -w 2 %s > %s 2> /tmp/debug", i, i, destName, fname);
	system(cmdString);
	/*	fprintf(stderr, "%s\n", cmdString); */


	FILE *fp = fopen(fname, "r");
	char line[MAX_LINE_SIZE];
	char *res = fgets(line, MAX_LINE_SIZE, fp);
	int hop;
	char ip[20];
	struct in_addr ipAddr;
	char dist[20];
	float lat;

	fclose(fp);
	assert(sscanf(line, "%d %s", &hop, ip) == 2);
	assert(hop == i);
	if (strcmp(ip, "*") == 0) {
	    ipAddr.s_addr = 0;
	    nqueries++;
	    SetDestHopInfo(dest, i-1, 0, ipAddr, 0, 0, nqueries, NULL);
	} else {
	    int pos;
	    assert(sscanf(line, "%d %s %s %n", &hop, ip, dist, &pos) == 3);
	    if (sscanf(dist, "%f", &lat) == 1) {
		ipAddr.s_addr = my_inet_aton(ip);
		SetDestHopInfo(dest, i-1, 1, ipAddr, lat, 0, nqueries, NULL);
		if (strncmp(line + pos, "ms !", 4) == 0)
		    break;
	    } else {
		assert(0);
	    }
	    nqueries = 0;
	}
	if (strcmp(ip, destName) == 0)
	    break;

	/* probe at least three times if there is no response */
	if (nqueries == 0 || nqueries == MAX_QUERIES) {
#if 1
	    printf("%15s ", ip);
	    fflush(stdout);
#endif
	    i++;
	    if (nqueries == MAX_QUERIES) {
		fails++;
		if (fails == MAX_FAILS)
		    break;
	    } else {
		fails = 0;
	    }
	    nqueries = 0;
	}
    }
#if 1
    printf("\n");
#endif
    /*    printf("%s\n", cmdString); 
	  fflush(stdout); */
    sprintf(cmdString, "rm -f .tmp_%d", destNo);
    system(cmdString);
}

