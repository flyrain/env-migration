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

struct pointer
{
    int offset;
    uint32_t value;
};

struct object_node
{
    uint32_t addr;
    uint32_t range;
    int count;
    struct pointer** pointers;
};

#endif // PAGE_TREE_H
