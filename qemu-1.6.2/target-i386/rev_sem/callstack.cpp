#include "config_pemu.h"
#include<list>
#include<stack>
#include<stdio.h>
#include <stdlib.h> 
#include <string.h>
#include <map>
#include <string>
#include "linux.h"
using namespace std;


static list<unsigned int> g_callsite;
static list<unsigned int> g_callstack;
static stack<unsigned int> g_ret_stack;
static map<unsigned int, int> g_obj;
static map<unsigned int, string> g_heap_types;
static map<string, unsigned int> g_heap_types_s;

extern "C"{

void insert_callsite(unsigned int pc)
{
	g_callsite.push_back(pc);
}


void delete_callsite(void)
{
	if(g_callsite.size() != 0)
		g_callsite.pop_back();
	else{
		fprintf(stderr, "error in pop_call_addr");
		exit(0);
	}
}

void insert_retaddr(unsigned int pc)
{
	g_ret_stack.push(pc);
}

void delete_retaddr(unsigned int pc)
{
	g_ret_stack.pop();
}

void insert_callstack(unsigned int pc)
{
	g_callstack.push_back(pc);
}

void delete_callstack(void)
{
	g_callstack.pop_back();
}

int get_current_func(void)
{
	return g_callstack.back();
}

int is_retaddr(unsigned int pc)
{
	if(g_ret_stack.empty())
		return 0;
	if(g_ret_stack.top() == pc){
		//g_ret_stack.pop();
		return 1;
	}else {
		return 0;
	}
}

void dump_callsites(void)
{
	for(std::list<unsigned int>::iterator it = g_callsite.begin(); 
			it != g_callsite.end(); ++it){
		fprintf(stdout, "%x->", *it);
	}
	fprintf(stdout, "\n");
}

void dump_callstacks(void)
{
	for(std::list<unsigned int>::iterator it = g_callstack.begin(); 
			it != g_callstack.end(); ++it){
		fprintf(stdout, "%x->", *it);
	}
	fprintf(stdout, "\n");
}

void clear_calldata(void)
{
	g_callsite.clear();
	g_callstack.clear();
	
	while(!g_ret_stack.empty())
    	g_ret_stack.pop();
}


void ds_code_load_heapTypes(void)
{
#ifdef LINUX_2_6_32_8
	FILE *file = fopen("kmem_cache_linux.log", "r");
#endif
#ifdef FREEBSD
	FILE *file = fopen("kmem_cache_freebsd.log", "r");
#endif

	if(!file){
		fprintf(stderr, "error:\tcan't find kmem_cache_linux.log\n");
		return;
		exit(0);
	}


	char type[50];
	int num;
#ifdef FREEBSD
	char line[500];
	while(fgets(line, 500, file)){
		strcpy(type, strtok(line, "\t"));
		sscanf(strtok(NULL, "\t"), "%x", &num);
		if(g_heap_types.count(num-1)){
			//fprintf(stderr, "duplicate\t%x\n", type);
		}
		g_heap_types[num-1] = string(type);
		g_heap_types_s[type] = num-1;
		fprintf(stdout, "load\t%s\t%x\n", type, num);
	}
#else
	while(fscanf(file, "%s\t%x\n", type, &num) != EOF){
		if(g_heap_types.count(num-1)){
			fprintf(stderr, "duplicate\t%x\n", type);
		}
		g_heap_types[num-1] = type;
		g_heap_types_s[type] = num-1;
		fprintf(stdout, "load\t%s\t%x\n", type, num);
	}

#endif

	for(map<string, unsigned int>::iterator it = g_heap_types_s.begin();
			it != g_heap_types_s.end(); it++){
		//fprintf(stderr, "print\t%s\t%x\n", it->first.c_str(), it->second);
	}

}


}
