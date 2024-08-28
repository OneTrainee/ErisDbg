#pragma once
#include <ntifs.h>
#include "ept.h"
#include "ept2.h"

struct ProcessorSharedData {
	PVOID msrBitMap;
	PVOID ioBitMapA;
	PVOID ioBitMapB;
};

struct VCPU {
	PVOID pvmxon;
	PVOID pvmcs;
	PVOID p_host_stack;
	//PVOID p_bitmap_msr;

	// for ept2.h 
	struct EptData* ept_data; 

	// for ept1.h
	PVMX_MAMAGER_PAGE_ENTRY vmxMamgerPage;
	VMX_EPTP vmxEptp; 
};

struct ProcessorData {
	VCPU vcpus[128];
	ProcessorSharedData processorSharedData;
};


extern struct ProcessorData g_ProcessorData;

const unsigned int HOST_STACK_SIZE = PAGE_SIZE * 4;