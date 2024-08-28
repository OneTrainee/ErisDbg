#include <ntifs.h>
#include <intrin.h>
#include "hde/hde64.h"
#include "pagehook.h"
#include "UtilsVT.h"
#include "asm.h"
#include "NtExportFunction.h"
#include "VmxDefinition.h"

PageHookContext gPageHookContext = { 0 };

EXTERN_C PVOID PsGetProcessWow64Process(PEPROCESS Process);

BOOLEAN IsCurrentProcessX64()
{
	PEPROCESS Process = PsGetCurrentProcess();

	return PsGetProcessWow64Process(Process) == NULL;
}

ULONG GetWindowsVersionNumber()
{
	static ULONG gNumber = 0;
	if (gNumber != 0) return gNumber;

	RTL_OSVERSIONINFOW version = { 0 };
	RtlGetVersion(&version);

	if (version.dwMajorVersion <= 6) return 7;

	if (version.dwBuildNumber == 9600)
	{
		gNumber = 8;
	}
	else if (version.dwBuildNumber == 10240)
	{
		gNumber = 1507;
	}
	else if (version.dwBuildNumber == 10586)
	{
		gNumber = 1511;
	}
	else if (version.dwBuildNumber == 14393)
	{
		gNumber = 1607;
	}
	else if (version.dwBuildNumber == 15063)
	{
		gNumber = 1703;
	}
	else if (version.dwBuildNumber == 16299)
	{
		gNumber = 1709;
	}
	else if (version.dwBuildNumber == 17134)
	{
		gNumber = 1803;
	}
	else if (version.dwBuildNumber == 17763)
	{
		gNumber = 1809;
	}
	else if (version.dwBuildNumber == 18362)
	{
		gNumber = 1903;
	}
	else if (version.dwBuildNumber == 18363)
	{
		gNumber = 1909;
	}
	else if (version.dwBuildNumber == 19041)
	{
		gNumber = 2004;
	}
	else if (version.dwBuildNumber == 19042)
	{
		gNumber = 2009;
	}
	else if (version.dwBuildNumber == 19043)
	{
		gNumber = 2011;
	}
	else if (version.dwBuildNumber == 19044)
	{
		gNumber = 2012;
	}
	else if (version.dwBuildNumber == 22200)
	{
		gNumber = 2013;
	}


	return gNumber;
}

ULONG64 GetCurrentProcessUserCr3()
{
	PEPROCESS Process = PsGetCurrentProcess();

	ULONG number = GetWindowsVersionNumber();
	ULONG64 offset = 0;
	switch (number)
	{
	case 7:
		offset = 0x110;
		break;
	case 8:
	case 1507:
	case 1511:
	case 1607:
	case 1703:
	case 1709:
		offset = 0x278;
		break;
	case 1803:
	case 1809:
		offset = 0x280;
		break;
	case 1903:
	case 1909:
		offset = 0x280;
		break;
	case 2004:
	case 2009:
	case 2011:
	case 2012:
	case 2013:
		offset = 0x388;
		break;
	default:
		offset = 0x388;
		break;
	}

	ULONG64 userCr3 = *(PULONG64)((ULONG_PTR)Process + offset);

	if (userCr3 & 1 == 0)
	{
		userCr3 = 1;
	}

	return userCr3;
}

VOID EptInitPageHookContext(PPageHookContext context)
{
	memset(context, 0, sizeof(PageHookContext));

	ULONG64 kernelCr3 = __readcr3();

	ULONG64 userCr3 = GetCurrentProcessUserCr3();

	context->isHook = FALSE;

	context->KernelCr3 = kernelCr3;

	context->UserCr3 = userCr3;

	InitializeListHead(&context->list);
}

VOID EptPageHookVmCallDpc(_In_ struct _KDPC* Dpc, _In_opt_ PVOID DeferredContext, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2)
{
	PPageHookContext phContext = (PPageHookContext)DeferredContext;

	ULONG64 RetIsHook = 0;

	AsmVmCall(__EPT_PAGE_HOOK, phContext->KernelCr3, phContext->NewAddrPageNumber, phContext->OldFunAddrPageNumber, &RetIsHook);

	phContext->isHook = TRUE;

	DbgPrintEx(77, 0, "[db]:vt cpu number = %d hook %llx,isHook %lld\r\n", KeGetCurrentProcessorNumberEx(NULL), phContext->OldPageStartPage, RetIsHook);



	KeSignalCallDpcDone(SystemArgument1);
	KeSignalCallDpcSynchronize(SystemArgument2);
}

PPageHookContext EptGetPageHookContext(ULONG64 funAddrStartPage, ULONG64 kernelCr3, ULONG64 userCr3)
{

	if (funAddrStartPage == 0) return NULL;

	PPageHookContext headList = (PPageHookContext)&gPageHookContext.list;

	PPageHookContext next = headList;

	PPageHookContext findContext = NULL;

	if (IsListEmpty(reinterpret_cast<const LIST_ENTRY*>(headList))) return NULL;

	do
	{

		if (reinterpret_cast<ULONG64>(next->OldPageStartPage) == funAddrStartPage)
		{
			if (next->isKernelHook)
			{
				findContext = next;
				break;
			}

			if (next->KernelCr3 == kernelCr3 || (userCr3 != 1 && next->UserCr3 == userCr3))
			{
				findContext = next;
				break;
			}
		}



		next = reinterpret_cast<PPageHookContext>(next->list.Flink);

	} while (next != headList && next != NULL);

	return findContext;
}

PPageHookContext EptGetPageHookContextByAddress(void* address) {

	auto const funAddrStartPage = (reinterpret_cast<ULONG64>(address) >> 12) << 12;

	if (funAddrStartPage == 0) return NULL;

	PPageHookContext headList = (PPageHookContext)&gPageHookContext.list;

	PPageHookContext next = headList;

	PPageHookContext findContext = NULL;

	if (IsListEmpty(reinterpret_cast<const LIST_ENTRY*>(headList))) return NULL;

	do
	{

		if (reinterpret_cast<ULONG64>(next->OldPageStartPage) == funAddrStartPage)
		{
			if (next->isKernelHook)
			{
				findContext = next;
				break;
			}
		}



		next = reinterpret_cast<PPageHookContext>(next->list.Flink);

	} while (next != headList);

	return findContext;
}

BOOLEAN PageHookHandleBreakPoint(void* address) {

	ULONG64 funAddrStartPage = ((ULONG64)address >> 12) << 12;

	ULONG64 kernelCr3 = __readcr3();

	ULONG64 userCr3 = GetCurrentProcessUserCr3();

	PPageHookContext phContext = EptGetPageHookContext(funAddrStartPage, kernelCr3, userCr3);

	if (!phContext) {
		return FALSE;
	}

	PVOID rip = NULL;
	for (auto i = 0; i < phContext->HookCount; i++) {
		if (address == phContext->OldFunAddr[i]) {
			rip = phContext->NewAddr[i];
			break;
		}
	}

	if (!rip) {
		return FALSE;
	}

	UtilVmWrite(VmcsField::kGuestRip, reinterpret_cast<ULONG_PTR>(rip));
	return TRUE;
}

BOOLEAN EptPageHook3(PVOID funAddr, PVOID* auxiliary_Function, PVOID newAddr) {
	if (!MmIsAddressValid(funAddr) || !MmIsAddressValid(newAddr))
	{
		return FALSE;
	}

	ULONG64 funAddrStartPage = ((ULONG64)funAddr >> 12) << 12;

	ULONG64 kernelCr3 = __readcr3();

	ULONG64 userCr3 = GetCurrentProcessUserCr3();



	if (gPageHookContext.list.Flink == 0)
	{
		InitializeListHead(&gPageHookContext.list);
	}

	PPageHookContext phContext = EptGetPageHookContext(funAddrStartPage, kernelCr3, userCr3);

	if (!phContext)
	{
		phContext = reinterpret_cast<PPageHookContext>(ExAllocatePool(NonPagedPool, sizeof(PageHookContext)));

		if (!phContext) return FALSE;

		EptInitPageHookContext(phContext);

		phContext->OldPageStartPage = reinterpret_cast<PUCHAR>(funAddrStartPage);

		//
	}


	phContext->OldFunAddr[phContext->HookCount] = funAddr;

	phContext->NewAddr[phContext->HookCount] = newAddr;

	phContext->HookCount++;

	
	if (!phContext->NewPageStartPage)
	{
		PHYSICAL_ADDRESS heightPhy = { 0 };

		heightPhy.QuadPart = MAXULONG64;

		PUCHAR newPage = reinterpret_cast<PUCHAR>(MmAllocateContiguousMemory(PAGE_SIZE, heightPhy));

		//
		memcpy(newPage, reinterpret_cast<PVOID>(funAddrStartPage), PAGE_SIZE);

		phContext->NewPageStartPage = newPage;


		phContext->NewAddrPageNumber = MmGetPhysicalAddress(phContext->NewPageStartPage).QuadPart / PAGE_SIZE;

		phContext->OldFunAddrPageNumber = MmGetPhysicalAddress(reinterpret_cast<PVOID>(funAddrStartPage)).QuadPart / PAGE_SIZE;

	}

	ULONG64 codeOffset = (ULONG64)funAddr - funAddrStartPage;
	// HOOK
	BOOLEAN isX64 = IsCurrentProcessX64();

	if (funAddrStartPage > reinterpret_cast<ULONG64>(MmHighestUserAddress))
	{
		phContext->isKernelHook = TRUE;
	}

	if (isX64)
	{
		// DbgBreakPoint();

		PVOID TrampCode = ExAllocatePool(NonPagedPool, PAGE_SIZE);
		if (!TrampCode) {
			DbgPrint("[*] Failed to ExAllocatePool\n");
			return FALSE;
		}
		RtlZeroMemory(TrampCode, PAGE_SIZE);

		const int NumRetShellCode = 18;
		const int NumInt3ShellCode = 1;
		/*
			00007FF7CF361822 | 6A 00                                          | push 0                                  |
			00007FF7CF361824 | C70424 00000000                                | mov dword ptr ss:[rsp],0                |
			00007FF7CF36182B | C74424 04 00000000                             | mov dword ptr ss:[rsp+4],0              |
			00007FF7CF36181F | C3                                             | ret                                     |
		*/
		char RetShellCode[NumRetShellCode] = {
			0x6A,0x00,
			0xC7,0x04,0x24,0x00,0x00,0x00,0x00,
			0xC7,0x44,0x24,0x04,0x00,0x00,0x00,0x00,
			0xC3 };
		/*
			00007FF7CF361835 | 48:B8 8877665544332211                         | mov rax,1122334455667788                |
			00007FF7CF36183F | FFE0                                           | jmp rax                                 |
		*/
		char Int3ShellCode[NumInt3ShellCode] = {
			0xcc
		};

		// BOOLEAN EptPageHook2(PVOID funAddr, PVOID* auxiliary_Function, PVOID newAddr)
		hde64s hde64{ 0 };
		char* pStart = (char*)funAddr;
		int damagedBytes = 0; // �ƻ����ֽ�
		do {
			if (!hde64_disasm(&pStart[damagedBytes], &hde64)) {
				DbgPrint("[*] Failed to disasm\n");
				return FALSE;
			}
			damagedBytes += hde64.len;
			if (damagedBytes > NumInt3ShellCode) {
				break;
			}
		} while (1);

		*(PULONG32)(&RetShellCode[5]) = ((ULONG64)funAddr + damagedBytes) & 0xFFFFFFFF;
		*(PULONG32)(&RetShellCode[13]) = (((ULONG64)funAddr + damagedBytes) >> 32) & 0xFFFFFFFF;
		// *(PVOID*)(&Int3ShellCode[2]) = newAddr;

		memcpy(TrampCode, pStart, damagedBytes);
		memcpy(&((CHAR*)TrampCode)[damagedBytes], RetShellCode, NumRetShellCode);

		memcpy(phContext->NewPageStartPage + codeOffset, Int3ShellCode, NumInt3ShellCode);

		*auxiliary_Function = reinterpret_cast<PVOID>(TrampCode);
	}
	else {
		// 
	}

	//
	if (IsListEmpty(&phContext->list))
	{
		InsertTailList(&gPageHookContext.list, &phContext->list);
	}

	//
	KeGenericCallDpc(EptPageHookVmCallDpc, phContext);

	return TRUE;
}
