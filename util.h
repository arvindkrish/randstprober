#ifndef _UTIL_H
#define _UTIL_H

#define MAX_QUERIES 3
#define MAX_FAILS 3
#define MAX_HOPS 30
#define WAITTIME 2

void SendSingleProbe(Destination *dest, int destNo);
void ReadIPList(FILE *fp, DestList *dests, int maxDests);
void ReadSimpleIPList(FILE *fp, SimpleDestList *dests, int maxDests);
void ReadABIPList(FILE *fp, SimpleDestList *dests, int maxDests);
void ReadIPPrefix(FILE *fp, DestList *dests);

#if 0
#ifdef HAVE_FSTREAM
  #include <fstream>
#else
  #include <fstream.h>
#endif

#include "Arts.hh"
#include "ArtsIpPath.hh"
#include "ArtsIpPathData.hh"
#include "ArtsIpPathEntry.hh"

#include "ArtsPackageVersion.hh"
#ifndef NDEBUG
  #include "ArtsDebug.hh"
#endif

using namespace std;

void PrintArtsFile(char *src, DestList *dests, char *fileName);
#endif

#endif
