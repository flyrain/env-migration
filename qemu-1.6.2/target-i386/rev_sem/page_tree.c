#include "page_tree.h"
#include "pemu.h"

struct page_node page_trees[100];
int page_tree_no;

void get_page_tree_no(){
    pemu_debug("page tree no: %d\n", page_tree_no);
}
