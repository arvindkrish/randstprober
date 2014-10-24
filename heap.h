#ifndef _HEAP_H
#define _HEAP_H

class HeapNode {
 public:
    float cost;
    int *pos_ptr;
    void *item;
};

class Heap {
 public:
    Heap();
    Heap(int);
    ~Heap();
    void InsertElem(float cost, void *elem, int *pos);
    void *DeleteMin();
    void RemoveItem(int pos, void *it);
    void ChangeCost(int pos, float newcost);
    void PrintHeap();
    int IsEmpty();
    float PeekMinCost();
 private:
    int num_elems;
    int max_elems;
    HeapNode *nodes;
    void UpdatePosPtr(int pos);
    void PushUp(int pos);
    void PushDown(int pos);
};


#endif
