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


#if 0

void object_hook(int pc_start)
{
	uint32_t objsize = 0;
	uint32_t ret_addr;
	
	if(objsize = get_objsize(pc_start)){
		ds_code_insert_rb(PEMU_get_reg(XED_REG_EAX), objsize, objsize);
		set_objsize(pc_start);
		//fprintf(stdout, "%x\tinsert\t%x\n", pc_start, PEMU_get_reg(XED_REG_EAX));
	}
	
	if(pc_start == KMEM_CACHE_ALLOC){
		uint32_t tmp, tmp1;
		PEMU_read_mem(PEMU_get_reg(XED_REG_ESP), 4, &ret_addr);
#ifdef FREEBSD
		PEMU_read_mem(PEMU_get_reg(XED_REG_ESP) + 4, 4, &tmp);
		PEMU_read_mem(tmp, 4, &tmp);
		PEMU_read_mem(tmp, 50, name);
		objsize = find_heap_size(name) + 1;
#else
		tmp = PEMU_get_reg(XED_REG_EAX);
		PEMU_read_mem(tmp + 0x8, 4, &objsize);
		PEMU_read_mem(tmp + 0x54, 4, &tmp1);
//		PEMU_read_mem(tmp1, 50, name);
//		strcpy(name, find_heap_types(objsize - 1));
#endif
		set_objsize(ret_addr, objsize-1);
		//add_call_into_rbt(ret_addr, objsize-1);
		//fprintf(stdout, "0x%x\t0x%x\n", ret_addr, objsize);

	}else if(pc_start == KMEM_CACHE_FREE){
		uint32_t tmp, addr;
#ifdef FREEBSD
		PEMU_read_mem(PEMU_get_reg(XED_REG_ESP) + 8, 4, &addr);
		PEMU_read_mem(PEMU_get_reg(XED_REG_ESP) + 4, 4, &tmp);
		PEMU_read_mem(tmp, 4, &tmp);
		PEMU_read_mem(tmp, 50, name);
#else
		PEMU_read_mem(PEMU_get_reg(XED_REG_EAX) + 0x8, 4, &tmp);
//		strcpy(name, find_heap_types(tmp - 1));
		addr = PEMU_get_reg(XED_REG_EDX);
#endif	
		
		if(ds_code_delete_rb(addr)){
			//fprintf(stdout, "free\t%x\n", addr);
		}else{
			//fprintf(stdout, "error in free\t%x\n", addr);
		}
	}
}

void callstack_hook(int pc_start)
{
	if(xed_decoded_inst_get_iclass(&pemu_inst.PEMU_xedd_g) == XED_ICLASS_CALL_NEAR) {
		uint32_t target_pc = get_callDest(&pemu_inst.PEMU_xedd_g, pc_start);
		uint32_t retaddr = pc_start + xed_decoded_inst_get_length(&pemu_inst.PEMU_xedd_g);
		//insert_callsite(pc_start);	
		insert_retaddr(retaddr);
		insert_callstack(target_pc);
		//dump_callsites();	
		dump_callstacks();
	}
	if(is_retaddr(pc_start)) {
		//delete_callsite();
		delete_callstack();
		delete_retaddr();
		dump_callstacks();
	}
}
#endif

void helper_hook(int pc_start)
{
#ifdef OBJECT
//	object_hook(pc_start);
#endif

	if(!pemu_exec_stats.PEMU_main_start 
			&& pc_start > 0x8000000 && pc_start < 0x10000000
			&& pemu_exec_stats.PEMU_cr3 == PEMU_get_cr3()) {
			pemu_exec_stats.PEMU_main_start = 1;
			printf("\n--------------------main--------------------\n");
	}
	
	if(pc_start < 0xc0000000 || pemu_exec_stats.PEMU_main_start == 0) {
		return;
	}

	if(pemu_exec_stats.PEMU_start 
			&& pemu_exec_stats.PEMU_cr3 == PEMU_get_cr3()
			&& pemu_exec_stats.PEMU_start_trace_syscall == 1 
			&& pemu_exec_stats.PEMU_int_level == 0
			&& pc_start < 0xc0000000 ) {		
		if(disas_one_inst_ex(pc_start, &pemu_inst) == XED_ERROR_NONE) {
#ifdef TRACECALLSTACK
//			callstack_hook(pc_start);
#endif

#ifdef TAINT
			Instrument(pc_start, xed_decoded_inst_inst(&pemu_inst.PEMU_xedd_g));
#endif
		}
	}
}


