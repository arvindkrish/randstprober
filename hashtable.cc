#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <iostream>
using namespace std;
#include "hashtable.h"


HashTable::HashTable(int num)
{
    buckets = new OpenList *[num];
    for (int i=0; i<num; i++)
	buckets[i] = NULL;
    numBuckets = num;
}

unsigned int HashString(char *str)
{
    int n = strlen(str);
    unsigned h = str [0];
    for (int i = 1; str [i] != 0; ++i)
        h = h*31 + str[i];
    return h;
}

void *HashTable::Get(char *k)
{
    int pos = HashString(k) % numBuckets;
    if (buckets[pos] == NULL)
	return NULL;
    else
	return buckets[pos]->LookupKey(k);
}

int HashTable::Put(char *k, void *it)
{
    int pos = HashString(k) % numBuckets;
    if (buckets[pos] == NULL) {
	buckets[pos] = new OpenList(strdup(k), it);
	return 1;
    } else
	return buckets[pos]->AddToList(k, it);
}

void HashTable::Iter(void (*fun(char *, void *)))
{
    for (int i=0; i<numBuckets; i++) {
	OpenList *t = buckets[i];
	while (t) {
	    fun(t->GetKey(), t->GetItem());
	    t = t->GetNext();
	}
    }
}

#if 0
int main(int argc, char **argv)
{
    HashTable h;
    cout << h.Put("arvind", (void *)1) << endl;
    cout << h.Put("arvind", (void *)2) << endl;
    cout << h.Put("krish", (void *)34) << endl;
    int retVal = (int)h.Get("arvind");
    cout << retVal << endl;
    retVal = (int)h.Get("krish");
    cout << retVal << endl;
}
#endif
