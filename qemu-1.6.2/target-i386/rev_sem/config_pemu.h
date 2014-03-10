#ifndef CONFIG_PEMU_H
#define CONFIG_PEMU_H

#define PEMU_DEBUG
#define TIMMER

#define KMEM_CACHE_CREATE 0xc10aa5c8 /*address of kmem_cache_create*/
#define KMEM_CACHE_ALLOC 0xc10a9a1b /*address of kmem_cache_alloc*/
#define KMEM_CACHE_FREE	0xc10a997f  /*address of kmem_cache_free*/
#define LINUX_2_6_32_8

#define TRACECALLSTACK
#define TAINT
#define OBJECT

#endif
