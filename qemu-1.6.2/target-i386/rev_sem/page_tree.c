#include <stdbool.h>
#include "page_tree.h"
#include "pemu.h"

#define MAX_DATA_OBJECT_NODE 1024
struct object_node object_nodes[MAX_DATA_OBJECT_NODE];
int object_node_no = 0;

int print_obj()
{
    int i = 0;
    for (i = 0; i < object_node_no; i++) {
        pemu_debug("0x%x 0x%x object %d\n", object_nodes[i].addr, object_nodes[i].range, i);
    }
    return object_node_no;
}

static void connect_nodes(struct object_node *node, struct pointer* p)
{
    uint32_t source = node->addr;
    uint32_t target = p->value;
    uint32_t offset = p->offset;
    pemu_debug("(%x -> %x, o: %d)", source, target, offset);
    graph_output("\"%x\" -> \"%x\" [label=%d]\n", source, target, offset);
}

static void pointer_add(struct object_node *node, uint32_t offset, uint32_t value)
{
    pemu_debug("(p, %x:%d %x)", node->addr, offset, value );
    struct pointer * newpointer = malloc(sizeof(struct pointer));
    newpointer->offset = offset;
    newpointer->value = value;
    if(node->count == 0){
        node->count++;
        node->pointers = malloc(sizeof(struct pointer*));
        node->pointers[0] = newpointer;
    }else{
        node->count++;
        node->pointers = realloc(node->pointers, sizeof(struct pointer*) * node->count);
        node->pointers[node->count - 1] = newpointer;
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
    //find the nearest pointer related to addr
    int i = 0;
    int distance = -1;
    struct pointer * nearest_pointer = NULL;
    struct object_node * nearest_node = NULL;
    for (i = object_node_no - 1; i >= 0; i--) {
        struct object_node * node = &object_nodes[i];
        int j = 0;
        for (j = 0; j < node->count; j++) {
            struct pointer * curr = node->pointers[j];
            if(addr >= curr->value &&
               addr <= curr->value + 3*4096)
                if(distance == -1 || addr - curr->value < distance){
                    if(distance != -1)
                        pemu_debug("(distance: %d to %d)", distance, addr - curr->value);
                    nearest_pointer = curr;
                    nearest_node = node;
                    distance = addr - curr->value;
                }
        }
    }

    if(nearest_pointer != NULL){
        connect_nodes(nearest_node, nearest_pointer);
        return nearest_pointer;
    }

    return NULL;
}

static struct object_node* object_node_add(uint32_t addr, uint32_t range, int global)
{
    struct object_node* newnode = NULL;
    assert(object_node_no < MAX_DATA_OBJECT_NODE);
    object_nodes[object_node_no].addr = addr;
    object_nodes[object_node_no].range = range; 
    newnode = &object_nodes[object_node_no];
    if(global == 1){
        pemu_debug("(Global:%x, object no %d)", addr, object_node_no);
        graph_output("\"%x\" [shape=box color=red style=filled];\n", addr);
    }else{
        pemu_debug("(Heap:%x, object no %d)", addr, object_node_no);
        graph_output("\"%x\" [shape=ellipse color=yellow style=filled];\n", addr);
    }
    object_node_no ++;
    return newnode;
}

extern int is_lea;

void heap_access(uint32_t addr, uint32_t value)
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
            heap_node = object_node_add(curr_pointer->value, 
                                        addr - curr_pointer->value, 0);
        }else{
            pemu_debug("(Cannot find pointer to this object %x)", addr);
        }
    }

    if(is_lea){return;}

    if(heap_node != NULL){
        //renew the range of node
        if(addr - heap_node->addr > heap_node->range)
            heap_node->range = addr - heap_node->addr; 
        //add pointer to the heap node
        if(is_kernel_address(value))
            pointer_add(heap_node, addr - heap_node->addr, value);
    }
}

void global_access(uint32_t addr, uint32_t value)
{
    //In global area, each page is considered as a node heap area, we
    //should caculate the size and the start address of a object, also
    //then internal pointer should have offset which related to start
    //address of the object, and value of pointer which point out to
    //another object.
    struct object_node * new_node = find_global_node(addr);
    if(new_node == NULL){
        new_node = object_node_add((addr & (~ 0xfff)), 4096, 1);
    }

    if(is_lea){return;}

    //add pointer into node
    assert(new_node != NULL);
    if(is_kernel_address(value))
        pointer_add(new_node, (addr & 0xfff), value);
}
