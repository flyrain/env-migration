#include <stdbool.h>
#include "page_tree.h"
#include "pemu.h"

#define MAX_DATA_OBJECT_NODE 1024
struct object_node object_nodes[MAX_DATA_OBJECT_NODE];
int object_node_no = 0;

static void connect_nodes(uint32_t source, uint32_t target, uint32_t offset)
{
    pemu_debug("(%x -> %x, o: %d)\n", source, target, offset);
    graph_output("\"%x\" -> \"%x\" [label=%d]\n", source, target, offset);
}

static void add_pointer_to_node(struct object_node *new_node, uint32_t addr, uint32_t value)
{
    struct pointer * newpointer = malloc(sizeof(struct pointer));
    newpointer->offset = (addr & 0xfff);
    newpointer->value = value;
    newpointer->next = NULL;
    if(new_node->pointers == NULL){
        new_node->pointers = newpointer;
    }else{
        struct pointer * curr = new_node->pointers;
        while(curr->next != NULL){
            curr = curr->next;
        }
        curr->next = newpointer;
    }
}

static struct object_node* find_global_node(uint32_t addr)
{
    int i = 0;
    for (i = 0; i < object_node_no; i++) {
        if(addr >= object_nodes[i].addr &&
           addr <= object_nodes[i].addr + object_nodes[i].range)
            return &object_nodes[i];
    }
    return NULL;
}

static struct object_node* find_heap_node(uint32_t addr)
{
    int i = 0;
    for (i = 0; i < object_node_no; i++) {
        if(addr >= object_nodes[i].addr &&
           addr <= object_nodes[i].addr + 3*4096) //default max size
                                                  //is 3 pages
            return &object_nodes[i];
    }
    return NULL;
}

static struct pointer* find_pointers(uint32_t addr)
{
    int i = 0;
    for (i = object_node_no - 1; i >= 0; i--) {
        struct object_node * node = &object_nodes[i];
        struct pointer * curr = node->pointers;
        while(curr != NULL){
            if(addr >= curr->value &&
               addr <= curr->value + 3*4096){
                //connect 
                connect_nodes(node->addr, curr->value, curr->offset);
                return curr;
            }
            curr = curr->next;
        }
    }
    return NULL;
}

static struct object_node* new_object_node(uint32_t addr, uint32_t range, int global)
{
    struct object_node* newnode = NULL;
    assert(object_node_no < MAX_DATA_OBJECT_NODE);
    object_nodes[object_node_no].addr = addr;
    object_nodes[object_node_no].range = range; 
    newnode = &object_nodes[object_node_no];
    if(global == 1){
        pemu_debug("(Global:%x, object no %d\n)", addr, object_node_no);
        graph_output("\"%x\" [shape=box color=red style=filled];\n", addr);
    }else{
        pemu_debug("(Heap:%x, object no %d\n)", addr, object_node_no);
        graph_output("\"%x\" [shape=ellipse color=yellow style=filled];\n", addr);
    }
    object_node_no ++;
    return newnode;
}

static void heap_access(uint32_t addr, uint32_t value)
{
    //heap memory acess handle
    //if there is no object exist, then creat a object and
    //connect the object else add to its pointers
    struct object_node * heap_node = find_heap_node(addr);
    if(heap_node == NULL){
        //search all pointers, if addr is in one of pointer's range,
        //then create a new node, and print out the edeges
        struct pointer * curr_pointer = find_pointers(addr);
        if(curr_pointer != NULL){
            heap_node = new_object_node(curr_pointer->value, 
                                        addr - curr_pointer->value, 0);
        }else{
            pemu_debug("(Cannot find pointer to this object %x)\n", addr);
        }
    }

    //add pointer to the heap node
    if(heap_node != NULL){
        //renew the range of node
        if(addr - heap_node->addr > heap_node->range)
            heap_node->range = addr - heap_node->addr; 
        add_pointer_to_node(heap_node, addr, value);
    }
}

void record_object_node(uint32_t addr, int global)
{
    if(addr == 0 || (addr & (~ 0xfff)) < KERNEL_ADDRESS)
        return;

    uint32_t value = 0;
    PEMU_read_mem(addr, 4, &value);
    
    //In global area, each page is considered as a node heap area, we
    //should caculate the size and the start address of a object, also
    //then internal pointer should have offset which related to start
    //address of the object, and value of pointer which point out to
    //another object.
    if(global == 1){
        //global
        struct object_node * new_node = find_global_node(addr);
        if(new_node == NULL){
            new_node = new_object_node((addr & (~ 0xfff)), 4096, 1);
       }

        //add pointer into node
        assert(new_node != NULL);
        add_pointer_to_node(new_node, addr, value);
    }else if(global == 0){
        heap_access(addr, value);
    }

    return;
}
