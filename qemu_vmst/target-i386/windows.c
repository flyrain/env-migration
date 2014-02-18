#include "windows.h"
#include "winHook.h"
#include<stdio.h>
#include<malloc.h>
#include<stdlib.h>
#include<string.h>

CPUX86State *current_env;
PIMAGE_SECTION_HEADER pSections=NULL;
inline void updateEnv(CPUX86State * env)
{
	current_env=env;
}

int getdata(char * dest, target_ulong addr, uint32_t size)
{
	return cpu_memory_rw_debug(current_env, addr, dest, size, 0);
}


void dumpSection(target_ulong ntheaderaddr, IMAGE_NT_HEADERS *ntheader)
{

//	PIMAGE_SECTION_HEADER pSection = (uintptr)ntheader+FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader)+ntheader->FileHeader.SizeOfOptionalHeader;
	uint32_t size = sizeof(IMAGE_SECTION_HEADER)*ntheader->FileHeader.NumberOfSections;
	pSections = (PIMAGE_SECTION_HEADER)realloc(pSections, size);
	if(getdata(pSections, ntheaderaddr+FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader)+ntheader->FileHeader.SizeOfOptionalHeader,size)!=0)
            debug("Cant't read the sections\n");


	unsigned i;
	PIMAGE_SECTION_HEADER pSection=pSections;
	debug("number of section %d\n", ntheader->FileHeader.NumberOfSections);
	for(i=0; i<ntheader->FileHeader.NumberOfSections;i++, pSection++)
	{	
            debug("section %s %x %x\n", pSection->Name, pSection->VirtualAddress, pSection->Misc.VirtualSize);
	}
}

PIMAGE_SECTION_HEADER getEnclosingSection(target_ulong rva, IMAGE_NT_HEADERS *ntheader)
{

//	PIMAGE_SECTION_HEADER pSection = (uintptr)ntheader+FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader)+ntheader->FileHeader.SizeOfOptionalHeader;
	PIMAGE_SECTION_HEADER pSection = pSections; 
	unsigned i;
	for(i=0; i<ntheader->FileHeader.NumberOfSections;i++, pSection++)
	{

		debug("section is %s %x\n", pSection->Name, pSection->VirtualAddress);
		if(rva>=pSection->VirtualAddress &&rva<(pSection->VirtualAddress+pSection->Misc.VirtualSize))
				return pSection;
	}
	return NULL;
}

uint32_t getPtrFromRva(target_ulong rva, IMAGE_NT_HEADERS *ntheader, target_ulong mBase)
{
	PIMAGE_SECTION_HEADER pSection;
	pSection =getEnclosingSection(rva, ntheader);

	if(!pSection)
		return 0;

	uint32_t delta = pSection->VirtualAddress-pSection->PointerToRawData;
	debug("delta is %x\n", delta);

	return mBase-delta+rva;

}

uint32_t getDelta(target_ulong rva, IMAGE_NT_HEADERS *ntheader, target_ulong mBase)
{
	PIMAGE_SECTION_HEADER pSection;
	pSection =getEnclosingSection(rva, ntheader);

	if(!pSection)
		return 0;

	uint32_t delta = pSection->VirtualAddress-pSection->PointerToRawData;
	debug("delat is %x\n", delta);

	return delta;

}

int getAsciiz(target_ulong base, char *str)
{

        char c;
        unsigned i=0;
        do {
                if (getdata(str+i, base+i, sizeof(char))<0) {
                        debug("Could not load asciiz at %#x\n", base+i);
                        return -1;
                }
				if(!str[i])
                	break;
                i++;
        }while(i<256);

        return 0;
}


void InitImports(target_ulong mBase, IMAGE_NT_HEADERS * ntheader)
{
	PIMAGE_DATA_DIRECTORY ImportDir;
    target_ulong ImportTableAddress;
    uint32_t ImportTableSize;

	target_ulong ImportNameTable;
	target_ulong ImportAddressTable;

	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptors;
	unsigned ImportDescCount;
    unsigned i,j;

	ImportDir = &ntheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	
	ImportTableAddress = ImportDir->VirtualAddress+mBase;
	ImportTableSize = ImportDir->Size;

	if(ImportDir->Size==0)
		return;
	
	debug("ImportAddress is %x %x\n", ImportDir->VirtualAddress, ImportTableSize);

	ImportDescCount=ImportTableSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	ImportDescriptors = (PIMAGE_IMPORT_DESCRIPTOR)malloc(ImportTableSize);

	if(getdata(ImportDescriptors, ImportTableAddress, ImportTableSize)!=0)
	{
		debug("Can't read ImportDescriptors\n");
		return -1;
	}

	debug("ImportDescCount is %d \n", ImportDescCount);
	for(i=0; ImportDescriptors[i].FirstThunk && i<ImportDescCount;i++)
	{

		IMAGE_THUNK_DATA32 INaT;
		IMAGE_THUNK_DATA32 IAT;
		char str[256];
		if(getAsciiz(ImportDescriptors[i].Name+mBase, str)==0)
   			debug("Dll name is %s\n", str);

		ImportAddressTable = mBase+ImportDescriptors[i].FirstThunk;
		ImportNameTable=mBase+ImportDescriptors[i].OriginalFirstThunk;
		//debug("%x %x %x\n", ImportDescriptors[i].FirstThunk, ImportDescriptors[i].OriginalFirstThunk, sizeof(IMAGE_THUNK_DATA32));
		if(ImportDescriptors[i].OriginalFirstThunk==0)
			ImportNameTable=ImportAddressTable;
		j=0;
		do{
			getdata(&INaT, ImportNameTable+j*sizeof(IMAGE_THUNK_DATA32), sizeof(IMAGE_THUNK_DATA32));
			getdata(&IAT, ImportAddressTable+j*sizeof(IMAGE_THUNK_DATA32), sizeof(IMAGE_THUNK_DATA32));

			if(!INaT.u1.AddressOfData)
				break;
			if(INaT.u1.AddressOfData & IMAGE_ORDINAL_FLAG){
				uint32_t tmp = INaT.u1.AddressOfData &0xffff;
				debug("d\n", tmp);
			}else{
		    	target_ulong a=INaT.u1.AddressOfData+mBase;
		   		 uint32_t c=IAT.u1.AddressOfData;
		    	//uint32_t b=ImportAddressTable+j*sizeof(IMAGE_THUNK_DATA32)-mBase;
				if(getAsciiz(a+2, str)==0)
					debug("%s  %x %x %x\n", str,c, INaT.u1.AddressOfData, mBase);
			}
			j++;
		}while(INaT.u1.AddressOfData);
	}

}

void InitExports(target_ulong mBase, IMAGE_NT_HEADERS*ntheader)
{
	PIMAGE_DATA_DIRECTORY ExportDataDir;
	uintptr ExportTableAddress;
	uint32_t ExportTableSize;

	PIMAGE_EXPORT_DIRECTORY ExportDir;

	ExportDataDir = &ntheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
//	printf("export is %x %x\n", ExportDataDir->VirtualAddress, ExportDataDir->Size);
	ExportTableAddress = ExportDataDir->VirtualAddress +mBase;
	ExportTableSize = ExportDataDir->Size;

	if(ExportDataDir->Size==0)
		return;
	ExportDir = (PIMAGE_EXPORT_DIRECTORY)malloc(ExportTableSize);


//	uint32_t delta;
//	delta=getDelta(ExportDataDir->VirtualAddress, ntheader, mBase);
	getdata(ExportDir, ExportTableAddress, ExportTableSize);


	unsigned TblSize;
	uint32_t *Names;
	uint32_t *FcnPtrs;
	uint16_t *ordinals;

	TblSize = ExportDir->NumberOfFunctions * sizeof(uint32_t);
	Names = (uint32_t *) malloc(TblSize);
	FcnPtrs = (uint32_t *) malloc(TblSize);
	ordinals = (uint16_t *) malloc(TblSize);


	getdata(FcnPtrs, ExportDir->AddressOfFunctions+mBase, TblSize);
	getdata(Names, ExportDir->AddressOfNames+mBase, ExportDir->NumberOfNames*sizeof(uint32_t));
	getdata(ordinals, ExportDir->AddressOfNameOrdinals+mBase,ExportDir->NumberOfNames*sizeof(uint16_t));

	
	unsigned i,j;
	uint32_t exportStartRVA=ExportDataDir->VirtualAddress;
	uint32_t exportEndRVA = exportStartRVA +ExportDataDir->Size;

//	printf("%x\n", ExportDir->NumberOfFunctions);
	for(i=0;i<ExportDir->NumberOfFunctions;i ++)
	{	
		char fname[512];
		if(FcnPtrs[i]==0)
			continue;
		
		//See if this function has an associated name exported for it
		for(j=0;j <ExportDir->NumberOfNames;j++)
			if(ordinals[j]==i)
			{
				getAsciiz(Names[i]+mBase,fname);
				debug("%s ", fname);
			}
		debug("%x ", FcnPtrs[i]);
		//Is it a forwarder? If so, the entry point RVA is inside the 
		//.edata section, and is an RVA to the DllName.EntryPointName
		if((FcnPtrs[i] >=exportStartRVA)
				&& (FcnPtrs[i]<=exportEndRVA))
		{

			getAsciiz(FcnPtrs[i]+mBase,fname);
			debug("(forwarder -> %s)", FcnPtrs[i]+mBase);
		}

		debug("\n");

	}
}

int
pedump(target_ulong mbase, uint32_t size, CPUX86State *env)
{

	updateEnv(env);
	IMAGE_DOS_HEADER dosheader;
	if(getdata(&dosheader, mbase, sizeof(dosheader))!=0)
		return -1;

	if(dosheader.e_magic!=IMAGE_DOS_SIGNATURE)
	{
		debug("PE image has invalid magic\n");
		return -1;
	}

	IMAGE_NT_HEADERS ntheader;
	if(getdata(&ntheader, mbase+dosheader.e_lfanew, sizeof(ntheader))!=0)
		return -1;

	if(ntheader.Signature !=IMAGE_NT_SIGNATURE)
	{
		debug("NT header has invalid magic\n");
		return -1;
	}

	debug("PE file is %x %d %d\n", ntheader.OptionalHeader.ImageBase, ntheader.OptionalHeader.SizeOfImage, size);
	dumpSection(mbase+dosheader.e_lfanew, &ntheader);
	InitImports(mbase, &ntheader); 
	InitExports(mbase, &ntheader); 
	return 0;
}

ApiDataBase apis;

void formatStr(char *name)
{
	unsigned int i=strlen(name);
	unsigned int j;
	for(j=0;j<i;j++)
		name[j]=tolower(name[j]);
}
int init_dlls(char *fname)
{
	uint32_t size;
	FILE *fp;
	
	fp =fopen(fname, "r");
	if(fp==NULL)
	{
		debug("Can't open file %s\n", fname);
		return -1;
	}
	debug("start reading dll entry\n");
	fscanf(fp, "%x", &size);
	apis.dll=(DllEntry *)malloc(sizeof(DllEntry)*size);
	memset(apis.dll, 0, sizeof(DllEntry)*size);
	apis.numOfdlls = size;

	unsigned int i,j;
	for(i=0;i<size;i++)
	{
		fscanf(fp, "%s %x", apis.dll[i].dllname, &apis.dll[i].numOffcn);
		apis.dll[i].pfcn = (Function*)malloc(sizeof(Function)*apis.dll[i].numOffcn);
	    for(j=0;j<apis.dll[i].numOffcn;j++)
		{
			fscanf(fp, "%s %x", apis.dll[i].pfcn[j].Fname, &apis.dll[i].pfcn[j].addr);
		}
	}

	fclose(fp);	
	return 0;
}
DllEntry * find_dll_by_name(char *dllname)
{
	unsigned int i;
	for(i=0;i<apis.numOfdlls;i++)
		if(strcmp(dllname, apis.dll[i].dllname)==0)
			return (apis.dll+i);
    return NULL;
}
DllEntry * find_dll_by_addr(target_ulong addr)
{
	unsigned int i;
	for(i=0;i<apis.numOfdlls;i++)
		if(apis.dll[i].entry<=addr &&(addr <(apis.dll[i].size+apis.dll[i].entry)))
			return (apis.dll+i);
    return NULL;
}

void setDll(char*dllname, target_ulong addr, uint32_t size)
{
	formatStr(dllname);
	DllEntry *dll= find_dll_by_name(dllname);
	if(dll!=NULL){
		dll->entry=addr;
		dll->size =size;	
		debug("new dll %s %x %x\n", dllname, addr, size);
	}else{
		debug("NO such dll %s\n", dllname);
	}
}
Function * getFcnByAdd(DllEntry *dll, target_ulong addr)
{
		unsigned int j;
		target_ulong offset=addr-dll->entry;
		for(j=0;j<dll->numOffcn;j++)
			if(dll->pfcn[j].addr==offset)
				return (dll->pfcn+j);

		return NULL;
}

int getFcnName(target_ulong addr, char *fname)
{
	DllEntry *dll = find_dll_by_addr(addr);	
	if(dll!=NULL){
		Function *fcn = getFcnByAdd(dll, addr);
		if(fcn!=NULL)
		{
			printf("find %s\n", fcn->Fname);
			strcpy(fname, fcn->Fname);
			return 0;
		}
		else
			debug("unkonwn function in %s\n", dll->dllname);
	}else
		debug("Unknown address %x\n", addr);

	return -1;
}

//check whether api is in msvcrt.dll
//these api is self implemented by vC
int isApiImplememted(target_ulong addr)
{	
	DllEntry *dll = find_dll_by_addr(addr);	
	if(dll!=NULL)
		if(strcmp(dll->dllname,"msvcrt.dll")==0)
			return 1;
	return 0;
}

#if 0
#include <xed-interface.h>
xed_decoded_inst_t xedd_g;
/* Variables to keep disassembler state */
xed_state_t dstate;
xed_decoded_inst_t xedd;

/* XED2 initialization */
void xed2_init()
{
	 
	xed_decoded_inst_set_mode(&xedd_g, XED_MACHINE_MODE_LEGACY_32,
			XED_ADDRESS_WIDTH_32b);

	 xed_tables_init();
	 xed_state_zero(&dstate);

  	 xed_state_init(&dstate,XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b, XED_ADDRESS_WIDTH_32b);

}
#endif 
windows win;

typedef unsigned short TCHAR;
void unicode2ascii(TCHAR *str)
{
	char *dst = (char *) str;
 	while (*str)
 		*dst++ = *(char *)str++;
 	*dst = '\0';
}


void scanProcess(CPUX86State *env)
{
    if(win.m_hookCr3!=-1)
        return;

    KPRCB32 kprcb;
    KTHREAD32 kthread;
    EPROCESS32 eprocess;
    uint32_t i=0;

    if(cpu_memory_rw_debug(env,KPRCB_OFFSET, &kprcb, sizeof(KPRCB32),0)!=0)
        return;
	
    if(cpu_memory_rw_debug(env, kprcb.CurrentThread, &kthread, sizeof(KTHREAD32), 0)!=0)
        return;

    target_ulong  curprocess=kthread.ApcState.Process;
    target_ulong  leadptr=kthread.ApcState.Process + FIELD_OFFSET(EPROCESS32,ActiveProcessLinks);
	
    do{
        i++;
        if(i>200)
            break;
        if(cpu_memory_rw_debug(env, curprocess, &eprocess, sizeof(EPROCESS32), 0)!=0)
            return;
        if (eprocess.ActiveProcessLinks.Flink==0)
            return;
	//	debug("image is %x %x %x\n", curprocess, leadptr, eprocess.ActiveProcessLinks.Flink);

//		debug("image is %s\n", eprocess.ImageFileName);
        if(strcmp(eprocess.ImageFileName,win.m_hookApp)==0)
        {
            debug("Found process %s!\n", win.m_hookApp);
            PEB32 peb;
            PEB_LDR_DATA32 ldrdata;
            LDR_DATA_TABLE_ENTRY32 ldrentry;
            char init;

            if(cpu_memory_rw_debug(env, eprocess.Peb, &peb, sizeof(PEB32), 0)!=0)
                return;

            if(cpu_memory_rw_debug(env, peb.Ldr, &ldrdata, sizeof(PEB_LDR_DATA32), 0)!=0)
                return;

            if(ldrdata.Initialized!=1)
                return;

            target_ulong leadptr = peb.Ldr +FIELD_OFFSET(PEB_LDR_DATA32, InLoadOrderModuleList);
            target_ulong curptr=ldrdata.InLoadOrderModuleList.Flink;

            if(curptr==0)
                return;
			
            do{
                char dllname[1024];	
                memset(dllname, 0, sizeof(dllname));
                if(cpu_memory_rw_debug(env,curptr,&ldrentry, sizeof(LDR_DATA_TABLE_ENTRY32), 0)!=0)
                    return;
                if(cpu_memory_rw_debug(env, ldrentry.BaseDllName.Buffer,dllname, ldrentry.BaseDllName.Length,0)!=0)
                    return;
                unicode2ascii(dllname);
                debug("User: Dll is %s %x %x %x\n", dllname, ldrentry.DllBase, ldrentry.SizeOfImage, ldrentry.EntryPoint);
                if(strcmp(dllname, win.m_hookApp)==0)
                {
                    win.mbase=ldrentry.DllBase;
                    win.msize=ldrentry.SizeOfImage;
                    win.mstart=ldrentry.EntryPoint;
                    win.m_hookCr3=eprocess.Pcb.DirectoryTableBase;
                    //init_top(win.mstart);  commented by yufei
                    return;
                }
                curptr=ldrentry.InLoadOrderLinks.Flink;
            }while(curptr!=leadptr);

            break;
        }	

        curprocess = CONTAINING_RECORD32(eprocess.ActiveProcessLinks.Flink, EPROCESS32, ActiveProcessLinks);
    }while(eprocess.ActiveProcessLinks.Flink!=leadptr);

}

void loadDll(CPUX86State *env)
{
			
		target_ulong pebptr;
		PEB32 peb;
		PEB_LDR_DATA32 ldrdata;
		LDR_DATA_TABLE_ENTRY32 ldrentry;

		if(cpu_memory_rw_debug(env, env->segs[R_FS].base+0x30, &pebptr, sizeof(pebptr), 0)!=0)
			return;
		
		if(cpu_memory_rw_debug(env, pebptr, &peb, sizeof(PEB32), 0)!=0)
			return;

		if(cpu_memory_rw_debug(env, peb.Ldr, &ldrdata, sizeof(PEB_LDR_DATA32), 0)!=0)
			return;

		if(ldrdata.Initialized!=1)
			debug("error\n");

		target_ulong leadptr = peb.Ldr +FIELD_OFFSET(PEB_LDR_DATA32, InLoadOrderModuleList);
		target_ulong curptr=ldrdata.InLoadOrderModuleList.Flink;

		if(curptr==0)
			return;
	
			
		do{
			char dllname[1024];	
			memset(dllname, 0, sizeof(dllname));
			if(cpu_memory_rw_debug(env,curptr,&ldrentry, sizeof(LDR_DATA_TABLE_ENTRY32), 0)!=0)
				return;
			if(cpu_memory_rw_debug(env, ldrentry.BaseDllName.Buffer,dllname, ldrentry.BaseDllName.Length,0)!=0)
				return;
			unicode2ascii(dllname);
			debug("load Dll is %s %x %x %x\n", dllname, ldrentry.DllBase, ldrentry.SizeOfImage, ldrentry.EntryPoint);
			if(strcmp(dllname, win.m_hookApp)!=0)
			{
				setDll(dllname,ldrentry.DllBase, ldrentry.SizeOfImage);
	//			if(strcmp(dllname, "ws2_32.dll")==0)
	//				pedump(ldrentry.DllBase, ldrentry.SizeOfImage,env);
			}
			curptr=ldrentry.InLoadOrderLinks.Flink;
		}while(curptr!=leadptr);

}

void init_process(char *pname)
{
	strcpy(win.m_hookApp, pname);
	strcat(win.m_hookApp, ".exe");
	debug("Start monitor process %s\n",win.m_hookApp);
	win.m_hookCr3=-1;
	win.mbase=-1;
	win.mstart=-1;
	win.msize =0;
	win.mainEntry=0;
}

//yang.new
target_ulong getImageRange()
{
	return win.mbase+win.msize;
}

