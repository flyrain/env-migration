#include "disas.h"
//#include "../hashTable.h"


xed_error_enum_t disas_one_inst_ex(target_ulong pc, struct PEMU_INST *inst)
{
	PEMU_read_mem(pc, 15, inst->PEMU_inst_buf);
	xed_decoded_inst_zero_set_mode(&inst->PEMU_xedd_g, &inst->PEMU_dstate);
	xed_error_enum_t xed_error = xed_decode(&inst->PEMU_xedd_g,
			XED_STATIC_CAST(const xed_uint8_t *, inst->PEMU_inst_buf), 15);
	return xed_error;	
}
