//#include "rb_tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "heap_shadow.h"
#include "config_pemu.h"
//#include "taint.h"
#define SENTINEL &sentinel      // all leafs are sentinels

#define UInt unsigned int

static NodeType sentinel = { SENTINEL, SENTINEL, 0, BLACK, 0};

static NodeType *root = SENTINEL; // root of red-black tree

static void rotateLeft(NodeType *x) {

    // rotate node x to left

    NodeType *y = x->right;

    // establish x->right link
    x->right = y->left;
    if (y->left != SENTINEL) y->left->parent = x;

    // establish y->parent link
    if (y != SENTINEL) y->parent = x->parent;
    if (x->parent) {
        if (x == x->parent->left)
            x->parent->left = y;
        else
            x->parent->right = y;
    } else {
        root = y;
    }

    // link x and y
    y->left = x;
    if (x != SENTINEL) x->parent = y;
}

static void rotateRight(NodeType *x) {

    // rotate node x to right

    NodeType *y = x->left;

    // establish x->left link
    x->left = y->right;
    if (y->right != SENTINEL) y->right->parent = x;

    // establish y->parent link
    if (y != SENTINEL) y->parent = x->parent;
    if (x->parent) {
        if (x == x->parent->right)
            x->parent->right = y;
        else
            x->parent->left = y;
    } else {
        root = y;
    }

    // link x and y
    y->right = x;
    if (x != SENTINEL) x->parent = y;
}

static void insertFixup(NodeType *x) {

    // maintain red-black tree balance
    // after inserting node x

    // check red-black properties
    while (x != root && x->parent->color == RED) {
        // we have a violation
        if (x->parent == x->parent->parent->left) {
            NodeType *y = x->parent->parent->right;
            if (y->color == RED) {

                // uncle is RED
                x->parent->color = BLACK;
                y->color = BLACK;
                x->parent->parent->color = RED;
                x = x->parent->parent;
            } else {

                // uncle is BLACK
                if (x == x->parent->right) {
                    // make x a left child
                    x = x->parent;
                    rotateLeft(x);
                }

                // recolor and rotate
                x->parent->color = BLACK;
                x->parent->parent->color = RED;
                rotateRight(x->parent->parent);
            }
        } else {

            // mirror image of above code
            NodeType *y = x->parent->parent->left;
            if (y->color == RED) {

                // uncle is RED
                x->parent->color = BLACK;
                y->color = BLACK;
                x->parent->parent->color = RED;
                x = x->parent->parent;
            } else {

                // uncle is BLACK
                if (x == x->parent->left) {
                    x = x->parent;
                    rotateRight(x);
                }
                x->parent->color = BLACK;
                x->parent->parent->color = RED;
                rotateLeft(x->parent->parent);
            }
        }
    }
    root->color = BLACK;
}

// insert new node (no duplicates allowed)
static RbtStatus rbtInsert(KeyType key, KeyType size, heap_shadow_node_t *p) {
    NodeType *current, *parent, *x;
    // allocate node for data and insert in tree

    // find future parent
    current = root;
    parent = 0;
    while (current != SENTINEL) {
        if (compEQ(key, current->key))
        {
			if(compEQ(size, current->size))
				return RBT_STATUS_DUPLICATE_KEY;
			else if (compLT(size, current->size))
				return RBT_STATUS_REALLOC_SMALL;
			else
				return RBT_STATUS_REALLOC_LARGE;
		}
        parent = current;
        current = compLT(key, current->key) ?
            current->left : current->right;
    }

    // setup new node
    if ((x = (NodeType*)malloc (sizeof(*x))) == 0)
		return RBT_STATUS_MEM_EXHAUSTED;

    x->parent = parent;
    x->left = SENTINEL;
    x->right = SENTINEL;
    x->color = RED;
    x->key = key;
    x->size = size;
	x->val = p;
//  x->val.type = p->type;
//  x->val.shadow_size = p->shadow_size;
//	x->val.start_addr = p->start_addr;


	// insert node in tree
    if(parent) {
        if(compLT(key, parent->key))
            parent->left = x;
        else
            parent->right = x;
    } else {
        root = x;
    }
    
	insertFixup(x);

    return RBT_STATUS_OK;
}

static void deleteFixup(NodeType *x) {

    // maintain red-black tree balance
    // after deleting node x

    while (x != root && x->color == BLACK) {
        if (x == x->parent->left) {
            NodeType *w = x->parent->right;
            if (w->color == RED) {
                w->color = BLACK;
                x->parent->color = RED;
                rotateLeft (x->parent);
                w = x->parent->right;
            }
            if (w->left->color == BLACK && w->right->color == BLACK) {
                w->color = RED;
                x = x->parent;
            } else {
                if (w->right->color == BLACK) {
                    w->left->color = BLACK;
                    w->color = RED;
                    rotateRight (w);
                    w = x->parent->right;
                }
                w->color = x->parent->color;
                x->parent->color = BLACK;
                w->right->color = BLACK;
                rotateLeft (x->parent);
                x = root;
            }
        } else {
            NodeType *w = x->parent->left;
            if (w->color == RED) {
                w->color = BLACK;
                x->parent->color = RED;
                rotateRight (x->parent);
                w = x->parent->left;
            }
            if (w->right->color == BLACK && w->left->color == BLACK) {
                w->color = RED;
                x = x->parent;
            } else {
                if (w->left->color == BLACK) {
                    w->right->color = BLACK;
                    w->color = RED;
                    rotateLeft (w);
                    w = x->parent->left;
                }
                w->color = x->parent->color;
                x->parent->color = BLACK;
                w->left->color = BLACK;
                rotateRight (x->parent);
                x = root;
            }
        }
    }
    x->color = BLACK;
}

// delete node
static RbtStatus rbtErase(NodeType * z) {
    NodeType *x, *y;

    if (z->left == SENTINEL || z->right == SENTINEL) {
        // y has a SENTINEL node as a child
        y = z;
    } else {
        // find tree successor with a SENTINEL node as a child
        y = z->right;
        while (y->left != SENTINEL) y = y->left;
    }

    // x is y's only child
    if (y->left != SENTINEL)
        x = y->left;
    else
        x = y->right;

    // remove y from the parent chain
    x->parent = y->parent;
    if (y->parent)
        if (y == y->parent->left)
            y->parent->left = x;
        else
            y->parent->right = x;
    else
        root = x;

    if (y != z) {
        z->key = y->key;
        z->size = y->size;
		z->val = y->val;
        //z->val.type = y->val.type;
        //z->val.shadow_size = y->val.shadow_size;
    }


    if (y->color == BLACK)
        deleteFixup (x);

    free (y);

    return RBT_STATUS_OK;
}

// find key
static NodeType *rbtFind(KeyType key) {
    NodeType *current;
    current = root;
    while(current != SENTINEL) {
        if(compEQ(key, current->key)) {
            return current;
        } else {
            current = compLT (key, current->key) ?
                current->left : current->right;
        }
    }
    return NULL;
}

// in-order walk of tree
#if 0
static void rbtInorder(FILE *f, NodeType *p, void (callback)(NodeType *)) {
    if (p == SENTINEL) return;
    rbtInorder(f, p->left, callback);
    //callback(p);
    fprintf(f, "%x\t%x\t%x\n", p->val.start_addr, p->val.shadow_size, p->val.type);
	rbtInorder(f, p->right, callback);
}
#endif

static void rbtInorder(NodeType *node, RB_CALLBACK callback, void* p) {
    if (node == SENTINEL) return;
    rbtInorder(node->left, callback, p);
    callback(node, p);
    //fprintf((FILE*)p, "%x\t%x\t%p\n", node->key, node->size, node->val);
	rbtInorder(node->right, callback, p);
}

// delete nodes depth-first
static void rbtDelete(NodeType *p) {
    if (p == SENTINEL) return;
    rbtDelete(p->left);
    rbtDelete(p->right);
    free(p);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
#if 0
NodeType *ds_code_get_root()
{
	return root;
}

void ds_code_rb_dump(NodeType *p, FILE *file, int type) 
{
	if (p == SENTINEL) return;
	rbtInorder(p->left, file);
	if(type == p->val.type)
		fprintf(file, "%x:%x", p->val.start_addr, p->val.shadow_size+1);//, p->val.offset);
	rbtInorder(p->right, file);
}
#endif

// find key, also check the size
NodeType *ds_code_rbtFind2(KeyType key)
{
    NodeType *current;
    current = root;
    while(current != SENTINEL) {
        if(compLT(current->key, key) && compLT(key, current->key+current->size)) {
            return current;
        } else {
            current = compLT (key, current->key) ?
                current->left : current->right;
        }
    }
    return NULL;
}

#if 0
void ds_code_traverse(FILE *f)
{
	rbtInorder(f, root, 0);
}
#endif

void ds_code_traverse(RB_CALLBACK callback, void* p)
{
	rbtInorder(root, callback, p);
}


int ds_code_delete_rb(UInt start_addr)
{
	NodeType *p;
	if((p = ds_code_rbtFind2(start_addr)) != NULL){
//fprintf(stderr, "delete\t%x\n", p->val.start_addr);
		rbtErase(p);
#ifdef PHRASE_TWO
		clear_taint_source_heaps(start_addr, p->size+1);
#endif
		return 1;
	}else{
		//fprintf(stderr, "error in ds_code_delete_rb\n");
		return 0;
	}

}

//type: related to callstack;
void ds_code_insert_rb(UInt start_addr, UInt size, long type){
	if(ds_code_rbtFind2(start_addr) != NULL){
		return;
	}
//	heap_shadow_node_t* p = (heap_shadow_node_t*) malloc(sizeof(heap_shadow_node_t));
//	p->shadow_size = size;
//	p->start_addr = start_addr;
//	p->type = (void*)type;
	
	rbtInsert(start_addr, size, (void*)type);
#ifdef PHRASE_TWO
	//set_taint_source_heaps(start_addr, size+1);
#endif
}



void ds_code_load_rb(void)
{
	FILE *file = fopen("mem_range.log", "r");
	if(file == NULL){
		fprintf(stderr, "error in open mem_range\n");
		exit(0);
	}

	int pgd, hello;
	fscanf(file, "%x\n", &pgd);
//	fprintf(stderr, "page:\t%x\n", pgd);
	
	unsigned int addr, range, type;
	while(fscanf (file, "%x\t%x\t%x\n", &addr, &range, &type) != EOF){
		//fprintf(stdout, "%x\t%x\t%x\n", addr, range, type);
		ds_code_insert_rb(addr, range, type);
		//set_taint_source_heaps(addr, range+1);
	}

	fclose(file);
}
