#include "page_tree.h"
#include "pemu.h"

#define MAX_DATA_OBJECT_NODE 1024
struct object_node object_nodes[MAX_DATA_OBJECT_NODE];
int object_node_no = 0;

/*
void print_edge(struct edge edge_item)
{
    pemu_debug("(%x -> %x)\n", edge_item.source, edge_item.target);
    //If point to self, don't print it out.
    if((edge_item.source & (~ 0xfff)) != edge_item.target )
        graph_output("\"%x\" -> \"%x\" [label=%d]\n", (edge_item.source & (~ 0xfff)), edge_item.target, edge_item.source & 0xfff );
    edge_item.is_printed = 1;
}
*/

void connect_nodes(uint32_t addr, uint32_t value)
{

    
}

void record_object_node(uint32_t addr, int global)
{
    if(addr == 0 || (addr & (~ 0xfff)) < KERNEL_ADDRESS)
        return;

    uint32_t value = 0;
    PEMU_read_mem(addr, 4, &value);
    
    //1. record objects
    //global area, each page is considered as a node
    //heap area, we should caculate the size and the start address of
    //a object, also then internal pointer should have offset which
    //related to start address of the object, and value of pointer
    //which point out to another object.
    if(global == 1){
        //global
        object_nodes[object_node_no].addr = (addr & (~ 0xfff));
        object_nodes[object_node_no].range = 4096;   // one page
        
        struct pointer * newpointer = malloc(sizeof(struct pointer));
        newpointer->offset = (addr & 0xfff);
        newpointer->value = value;
        newpointer->next = NULL;
        if(object_nodes[object_node_no].pointers == NULL){
            object_nodes[object_node_no].pointers = newpointer;
        }else{
            struct pointer * curr = object_nodes[object_node_no].pointers;
            while(curr->next != NULL){
                curr = curr->next;
            }
            curr->next = newpointer;
        }
        
        object_node_no ++;
        
    }else if(global == 0){
        //heap
        object_nodes[object_node_no].addr = addr;
        object_nodes[object_node_no].range = 4; 
        object_node_no ++;
    }

    //2. connect objects
    connect_nodes(addr, value);
    return;
/*    
      int i = 0;
      for(; i < page_node_no; i ++){
      if(page_nodes[i].addr == (addr & (~ 0xfff)))
      return;
      }

      assert(page_node_no < MAX_DATA_PAGE_NODE);

      struct page_node * node = &(page_nodes[page_node_no]);
      node->addr = (addr & (~ 0xfff));
      if(global){//global
      node->global = 1;
      pemu_debug("Global:%x, page node no %d\n", node->addr, page_node_no);
      graph_output("\"%x\" [shape=box color=red style=filled];\n", node->addr);
        
      }else{//heap
      node->global = 0;
      pemu_debug("Heap:%x, page node no %d\n", node->addr, page_node_no);
      graph_output("\"%x\" [shape=ellipse color=yellow style=filled];\n", node->addr);
      }

      page_node_no ++;
*/
}
