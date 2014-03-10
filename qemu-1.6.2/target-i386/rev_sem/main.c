#include <stdio.h>
#include "pemu.h"
#include "callstack.h"
#include "parse_operand.h"
#include "config_pemu.h"
#include "qemu/host-utils.h"
#include "cpu.h"
#include "tcg-op.h"
#include "disas.h"

#include "helper.h"
#define GEN_HELPER 1
#include "helper.h"


void helper_hook(int pc_start)
{
    if(!pemu_exec_stats.PEMU_main_start 
       //&& pc_start > 0x8000000 && pc_start < 0x10000000
       && pemu_exec_stats.PEMU_cr3 == PEMU_get_cr3()) {
        pemu_exec_stats.PEMU_main_start = 1;
        pemu_debug("\n--------------------main--------------------\n");
    }
	
    if(pc_start < KERNEL_ADDRESS || pemu_exec_stats.PEMU_main_start == 0) {
        return;
    }

    if(pemu_exec_stats.PEMU_start 
       && pemu_exec_stats.PEMU_cr3 == PEMU_get_cr3()
       && pemu_exec_stats.PEMU_start_trace_syscall == 1 
       && pemu_exec_stats.PEMU_int_level == 0
        ) {		
        if(disas_one_inst_ex(pc_start, &pemu_inst) == XED_ERROR_NONE) {

#ifdef TAINT
            Instrument(pc_start, xed_decoded_inst_inst(&pemu_inst.PEMU_xedd_g));
#endif
        }
    }
}
