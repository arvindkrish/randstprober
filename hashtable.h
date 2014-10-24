#ifndef _HASHTABLE_H
#define _HASHTABLE_H

class OpenList {
 public:
    OpenList(char *k, void *it) {
	next = NULL;
	key = k;
	item = it;
    }
    
    int AddToList(char *k, void *it) {
	if (key == k)
	    return 0;
	else if (next == NULL) {
	    next = new OpenList(strdup(k), it);
	    return 1;
	} else
	    return next->AddToList(k, it);
    }
    
    void *LookupKey(char *k) {
	if (strcmp(key, k) == 0)
	    return item;
	else if (next == NULL)
	    return NULL;
	else
	    return next->LookupKey(k);
    }

    char *GetKey() { return key; }
    void *GetItem() { return item; }
    OpenList *GetNext() { return next; }
    
 private:
    OpenList *next;
    char *key;
    void *item;
};

class HashTable {
 public:
    HashTable(int num = 1007);
    void *Get(char *key);
    int Put(char *key, void *item);
    void Iter(void (*fun(char *, void *)));
    
 private:
    OpenList **buckets;
    int numBuckets;
};

#endif
