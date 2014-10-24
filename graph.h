#ifndef _GRAPH_H
#define _GRAPH_H

#include "hashtable.h"

typedef struct VertexStruct {
    char *info;
    struct EdgeListStruct *pred;
    struct EdgeListStruct *succ;
} Vertex;

typedef struct {
    float latency;
} Attributes;

typedef struct EdgeListStruct {
    Attributes attr;
    Vertex *node;
    struct EdgeListStruct *next;
} EdgeList;

typedef struct VertexListStruct{
    Vertex *node;
    struct VertexListStruct *next;
} VertexList;

class Graph {
 public:
    Graph();
    Vertex *AddVertex(char *);
    Vertex *FindVertex(char *);
    void AddEdge(char *, char *, Attributes);
    void PrintPossibleAliases();
    int NumNodes() { return numNodes; }
 private:
    struct VertexListStruct *nodes;
    HashTable *hl;
    int numNodes;
};

#endif
