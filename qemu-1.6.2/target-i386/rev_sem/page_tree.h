#ifndef PAGE_TREE_H
#define PAGE_TREE_H
#include <stdint.h>

struct offset_value
{
    int offset;
    uint32_t value;
};

struct page_node
{
    uint32_t addr;
    int global;
    struct offset_value point_out[1024];
};


#endif // PAGE_TREE_H
