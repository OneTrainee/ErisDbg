#pragma once
#include <ntifs.h>

#define _EPT_PAGE_HOOK_MAX 20

typedef struct _PageHookContext
{
	LIST_ENTRY list;

	PVOID NewAddr[_EPT_PAGE_HOOK_MAX];

	PVOID OldFunAddr[_EPT_PAGE_HOOK_MAX];

	ULONG64 HookCount;

	ULONG64 insLen;

	PUCHAR NewPageStartPage;

	PUCHAR OldPageStartPage;

	ULONG64 NewAddrPageNumber;

	ULONG64 OldFunAddrPageNumber;

	ULONG64 KernelCr3;

	ULONG64 UserCr3;

	ULONG64 isHook;

	ULONG64 isKernelHook;
}PageHookContext, * PPageHookContext;

PPageHookContext EptGetPageHookContext(ULONG64 funAddrStartPage, ULONG64 kernelCr3, ULONG64 userCr3);

BOOLEAN EptPageHook(PVOID funAddr, PVOID newAddr);

// X64 Hook
BOOLEAN EptPageHook2(PVOID funAddr, PVOID* auxiliary_Function, PVOID newAddr);

// 
BOOLEAN EptPageHook3(PVOID funAddr, PVOID* auxiliary_Function, PVOID newAddr);

// 
BOOLEAN PageHookHandleBreakPoint(void* address);