/**********************************************************************************************
*      This file is part of X-Force, A Brute Force Execution Approach for Malware Analysis    *
*                                                                                             *
*      X-Force is owned and copyright (C) by Lab FRIENDS at Purdue University, 2009-2011.     *
*      All rights reserved.                                                                   *
*      Do not copy, disclose, or distribute without explicit written                          *
*      permission.                                                                            *
*                                                                                             *
*      Author: Zhiqiang Lin <zlin@cs.purdue.edu>                                              *
**********************************************************************************************/


//#define DEBUG_TAINT



#include "taint.h"
#include <stdlib.h>
#include "qemu-common.h"
/*---------------------shadow memory----------------------*/
#define PAGE_BITS 16
#define PAGE_SIZE (1<<PAGE_BITS)
#define PAGE_NUM  (1<<16)

#define IS_DISTINGUISHED_SM(smap) \
   ((smap) == &distinguished_secondary_map)

#define ENSURE_MAPPABLE(map, addr)                              \
   do {                                                           \
      if (IS_DISTINGUISHED_SM(map[addr >> 16])) {       \
         map[addr >> 16] = alloc_secondary_map; \
      }                                                           \
   } while(0)

#define ENSURE_MAPPABLE_BYTE_GRANUITY(map,addr)         \
   do {                                                           \
      if (IS_DISTINGUISHED_SM(map[addr >> 16])) {    \
          map[addr >> 16] = alloc_secondary_map(); \
      }                                                           \
   } while(0)


typedef struct {
   unsigned int byte[PAGE_SIZE];
} SecMap;

static SecMap distinguished_secondary_map;

static SecMap * ii_primary_map[PAGE_NUM];

static unsigned int shadow_bytes;


static void init_shadow_memory(void)
{
    Int i,j;

    for (i = 0; i< PAGE_SIZE; i++)
       distinguished_secondary_map.byte[i] = UNTAINTED; //0xff

      for (i = 0; i < PAGE_NUM; i++) {
        ii_primary_map[i] = &distinguished_secondary_map;
      }
}

static void free_shadow_memory(void)
{
    Int i,j;

      for (i = 0; i < PAGE_NUM; i++) {
        if(ii_primary_map[i] != &distinguished_secondary_map)
        {
			free(ii_primary_map[i]);
        }
      }
}


static SecMap* alloc_secondary_map ()
{
   SecMap* map;
   UInt  i;

   /* Mark all bytes as invalid access and invalid value. */
   map = (SecMap *)malloc(sizeof(SecMap));
   shadow_bytes+=sizeof(SecMap);
   for (i = 0; i < PAGE_SIZE; i++)
      map->byte[i] = UNTAINTED; /* Invalid Value */

   return map;
}

unsigned int  get_objsize(Addr a)
{
   
   SecMap* sm;
   sm= ii_primary_map[a>>16];

   UInt    sm_off = a & 0xFFFF;
   return  sm->byte[sm_off];
}

void  set_objsize(Addr a, unsigned int bytes)
{
   SecMap* sm;
   UInt    sm_off;
   ENSURE_MAPPABLE_BYTE_GRANUITY(ii_primary_map, a);
   sm    = ii_primary_map[a >> 16];

   sm_off = a & 0xFFFF;
   sm->byte[sm_off] = bytes;
}

void objInit(void)
{
	init_shadow_memory();
	//printf("objInit\n");
}
