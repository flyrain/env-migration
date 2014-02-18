#ifndef CONDITION_H
#define CONDITION_H

#include "cpu.h"


static inline int is_cf_set(){
	struct CPUX86State* cpu_single_env = (struct CPUX86State*)(first_cpu->env_ptr);
	return (cpu_single_env->eflags & CC_C) ? 1 : 0;
}


static inline int is_pf_set(){
	struct CPUX86State* cpu_single_env = (struct CPUX86State*)(first_cpu->env_ptr);
	return (cpu_single_env->eflags & CC_P) ? 1 : 0;
}


static inline int is_af_set(){
	struct CPUX86State* cpu_single_env = (struct CPUX86State*)(first_cpu->env_ptr);
	return (cpu_single_env->eflags & CC_A) ? 1 : 0;
}


static inline int is_zf_set(){
	struct CPUX86State* cpu_single_env = (struct CPUX86State*)(first_cpu->env_ptr);
	return (cpu_single_env->eflags & CC_Z) ? 1 : 0;
}


static inline int is_sf_set(){
	struct CPUX86State* cpu_single_env = (struct CPUX86State*)(first_cpu->env_ptr);
	//printf("is_sf_set:%d\n", cpu_single_env->eflags & CC_S);
	return (cpu_single_env->eflags & CC_S) ? 1 : 0;
}


static inline int is_of_set(){
	struct CPUX86State* cpu_single_env = (struct CPUX86State*)(first_cpu->env_ptr);
	//printf("is_of_set:%d\n", cpu_single_env->eflags & CC_O);
	return (cpu_single_env->eflags & CC_O) ? 1 : 0;
}
#endif
