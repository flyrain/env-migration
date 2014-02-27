#ifndef PAGE_TREE_H
#define PAGE_TREE_H
#include <inttypes.h>
//#include "qemu-common.h"

struct page_node;

struct offset_page_node
{
    int offset;
    struct page_node * next;
};

struct page_node
{
    uint32_t addr;
    struct offset_page_node point_out[1024];
};


#endif // PAGE_TREE_H
