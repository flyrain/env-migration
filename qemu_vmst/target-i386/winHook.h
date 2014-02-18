#ifndef WINHOOK_H
#define WINHOOK_H

#include"qemu-common.h"

/*
extern target_ulong m_hookCr3;
extern target_ulong mbase;
extern target_ulong mstart;
extern uint32_t msize;
extern char m_hookApp[];
extern target_ulong mainEntry;
*/
typedef struct windows{
	target_ulong m_hookCr3;
	target_ulong mbase;
	target_ulong mstart;
	uint32_t msize;
	char m_hookApp[512];
	target_ulong mainEntry;
}windows;

extern windows win;

void scanProcess(CPUX86State *env);
void loadDll(CPUX86State *env);
void init_process(char *pname);
int getFcnName(target_ulong addr, char *fname);
int getAsciiz(target_ulong base, char *str);
int isApiImplememted(target_ulong addr);

extern FILE * vmmi_log;
#define debug(...) do {                 \
        if (vmmi_log)                                                  \
        {	fprintf(vmmi_log, ## __VA_ARGS__); fflush(vmmi_log);} \
    } while(0)

#endif // WINHOOK_H
