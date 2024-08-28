#include "SearchCode.h"
#include <ntimage.h>
#include "Log.h"

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY RUNTIME_FUNCTION, * PRUNTIME_FUNCTION;


typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,             // obsolete...delete
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;                 // Not filled in
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

EXTERN_C NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
);


static UCHAR hexs[] =
{
	0x0, 0x1, 0x2, 0x3,
	0x4, 0x5, 0x6, 0x7,
	0x8, 0x9, 0xA, 0xB,
	0xC, 0xD, 0xE, 0xF
};

UCHAR charToHex(UCHAR* ch)
{
	unsigned char temps[2] = { 0 };
	for (int i = 0; i < 2; i++)
	{
		if (ch[i] >= '0' && ch[i] <= '9')
		{
			temps[i] = (ch[i] - '0');
		}
		else if (ch[i] >= 'A' && ch[i] <= 'F')
		{
			temps[i] = (ch[i] - 'A') + 0xA;
		}
		else if (ch[i] >= 'a' && ch[i] <= 'f')
		{
			temps[i] = (ch[i] - 'a') + 0xA;
		}
	}
	return ((temps[0] << 4) & 0xf0) | (temps[1] & 0xf);
}

void initFindCodeStruct(PFindCode findCode, PCHAR code, ULONG64 offset, ULONG64 lastAddrOffset)
{

	memset(findCode, 0, sizeof(FindCode));

	findCode->lastAddressOffset = lastAddrOffset;
	findCode->offset = offset;

	PCHAR pTemp = code;
	ULONG64 i = 0;
	for (i = 0; *pTemp != '\0'; i++)
	{
		if (*pTemp == '*' || *pTemp == '?')
		{
			findCode->code[i] = *pTemp;
			pTemp++;
			continue;
		}

		findCode->code[i] = charToHex(reinterpret_cast<UCHAR*>(pTemp));
		pTemp += 2;

	}

	findCode->len = i;
}


NTSTATUS GetNtModuleBaseAndSize(ULONG64* pModule, ULONG64* pSize)
{
	if (pModule == NULL || pSize == NULL) return STATUS_UNSUCCESSFUL;

	static ULONG64 KernelBase = 0;
	static ULONG64 KernelSize = 0;
	if (KernelBase && KernelSize)
	{
		*pModule = KernelBase;
		*pSize = KernelSize;
		return STATUS_SUCCESS;
	}


	RTL_PROCESS_MODULES errorModule = { 0 };
	ULONG resultSize = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, &errorModule, sizeof(RTL_PROCESS_MODULES), &resultSize);

	if (STATUS_INFO_LENGTH_MISMATCH == status)
	{
		PRTL_PROCESS_MODULES moules = (PRTL_PROCESS_MODULES)ExAllocatePool(PagedPool, resultSize + sizeof(RTL_PROCESS_MODULES));
		RtlZeroBytes(moules, resultSize + sizeof(RTL_PROCESS_MODULES));
		status = ZwQuerySystemInformation(SystemModuleInformation, moules, resultSize + sizeof(RTL_PROCESS_MODULES), &resultSize);



		if (NT_SUCCESS(status))
		{
			*pModule = reinterpret_cast<ULONG64>(moules[0].Modules->ImageBase);
			*pSize = moules[0].Modules->ImageSize;
			KernelBase = (ULONG64)moules[0].Modules->ImageBase;
			KernelSize = (ULONG64)moules[0].Modules->ImageSize;
			ExFreePool(moules);
		}

		//KdPrint(("KernelBase = %llx,KernelSize = %llx,status = %x\r\n", KernelBase, KernelSize, status));
		HYPERPLATFORM_LOG_INFO("KernelBase = %llx,KernelSize = %llx,status = %x", KernelBase, KernelSize, status);
	}


	return *pModule == NULL ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

ULONG64 findAddressByCode(ULONG64 beginAddr, ULONG64 endAddr, PFindCode  findCode, ULONG size)
{
	ULONG64 j = 0;
	LARGE_INTEGER rtna = { 0 };

	for (ULONG64 i = beginAddr; i <= endAddr; i++)
	{
		if (!MmIsAddressValid((PVOID)i))continue;


		for (j = 0; j < size; j++)
		{
			FindCode  fc = findCode[j];
			ULONG64 tempAddress = i;

			UCHAR* code = (UCHAR*)(tempAddress + fc.offset);
			BOOLEAN isFlags = FALSE;

			for (ULONG64 k = 0; k < fc.len; k++)
			{
				if (!MmIsAddressValid((PVOID)(code + k)))
				{
					isFlags = TRUE;
					break;
				}

				if (fc.code[k] == '*' || fc.code[k] == '?') continue;

				if (code[k] != fc.code[k])
				{
					isFlags = TRUE;
					break;
				}
			}

			if (isFlags) break;

		}

		//找到了
		if (j == size)
		{
			rtna.QuadPart = i;

			rtna.LowPart += findCode[0].lastAddressOffset;
			break;
		}

	}

	return rtna.QuadPart;
}

ULONG64 SearchNtCodeHead(PCHAR code, ULONG64 headOffset)
{

	FindCode fcs[1] = { 0 };
	initFindCodeStruct(&fcs[0], code, 0, headOffset);
	ULONG64 moudle = 0, size = 0;
	GetNtModuleBaseAndSize(&moudle, &size);
	if (moudle)
	{
		ULONG_PTR cdoex = findAddressByCode(moudle, moudle + size, fcs, 1);

		ULONG_PTR tempcdoex = cdoex;
		if (cdoex)
		{
			cdoex -= headOffset;
			PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moudle;
			PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)((PUCHAR)moudle + pDos->e_lfanew);
			PIMAGE_DATA_DIRECTORY pExceptDir = &pNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

			PRUNTIME_FUNCTION pRunTimeFunc = (PRUNTIME_FUNCTION)((PUCHAR)moudle + pExceptDir->VirtualAddress);
			int count = pExceptDir->Size / sizeof(RUNTIME_FUNCTION);
			PRUNTIME_FUNCTION find = NULL;

			BOOLEAN isFind = FALSE;
			for (int i = 0; i < count; i++)
			{
				ULONG64 startAddr = (pRunTimeFunc[i].BeginAddress + (ULONG64)moudle);
				ULONG64 endAddr = (pRunTimeFunc[i].EndAddress + (ULONG64)moudle);
				if (cdoex >= startAddr && cdoex <= endAddr)
				{


					PUCHAR pTemp = (PUCHAR)moudle + pRunTimeFunc[i].BeginAddress;;

					if ((pTemp[-1] == 0xCC && pTemp[-2] == 0xCC && pTemp[-3] == 0xCC && pTemp[-4] == 0xCC)
						|| (pTemp[-1] == 0x90 && pTemp[-2] == 0x90 && pTemp[-3] == 0x90 && pTemp[-4] == 0x90)
						)
					{
						cdoex = reinterpret_cast<ULONG_PTR>(pTemp);
						isFind = TRUE;
						break;
					}

				}

			}

			if (!isFind) cdoex = 0;

		}

		return cdoex == 0 ? tempcdoex : cdoex;
	}

	return 0;
}

ULONG64 SearchNtCodeVar(PCHAR code, ULONG64 headOffset)
{

	FindCode fcs[1] = { 0 };
	initFindCodeStruct(&fcs[0], code, 0, headOffset);
	ULONG64 moudle = 0, size = 0;
	GetNtModuleBaseAndSize(&moudle, &size);
	if (moudle)
	{
		ULONG_PTR cdoex = findAddressByCode(moudle, moudle + size, fcs, 1);

		return cdoex;
	}

	return 0;
}


ULONG64 SearchNtCode(PCHAR code)
{
	return SearchNtCodeHead(code, 0);
}

ULONG64 SearchCode(PCHAR code, ULONG_PTR saddr, ULONG_PTR size)
{
	FindCode fcs[1] = { 0 };
	initFindCodeStruct(&fcs[0], code, 0, 0);

	ULONG_PTR cdoex = findAddressByCode(saddr, saddr + size, fcs, 1);

	return cdoex;
}


ULONG64 findSpaceCode(ULONG64 BaseAddress)
{

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)BaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(BaseAddress + pDos->e_lfanew);

	PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((ULONG64)pNt + sizeof(pNt->Signature) + sizeof(pNt->FileHeader) + pNt->FileHeader.SizeOfOptionalHeader);
	UCHAR scodecc[36] = { 0 };
	PUCHAR isFind = 0;
	ULONG sheSize = sizeof(scodecc) / sizeof(UCHAR);
	for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		if ((pSection->Characteristics & 0x60000020) == 0x60000020)
		{
			PUCHAR start = reinterpret_cast<PUCHAR>(pSection->VirtualAddress + BaseAddress);
			ULONG64 SectionSize = pSection->SizeOfRawData % pNt->OptionalHeader.SectionAlignment;
			SectionSize = pNt->OptionalHeader.SectionAlignment - SectionSize + pSection->SizeOfRawData;
			PUCHAR end = reinterpret_cast<PUCHAR>(pSection->VirtualAddress + BaseAddress + SectionSize);
			for (; end != start; end--)
			{

				if (memcmp(end - sheSize, scodecc, sheSize) == 0)
				{
					isFind = end - sheSize;
					break;
				}
			}

			if (isFind) break;
		}

		pSection++;
	}

	return reinterpret_cast<ULONG64>(isFind);

}


ULONG GetWindowsVersionNumber2()
{
	static ULONG gNumberVer = -1;
	if (gNumberVer != -1) return gNumberVer;

	RTL_OSVERSIONINFOW version = { 0 };
	RtlGetVersion(&version);

	if (version.dwMajorVersion <= 6)
	{
		gNumberVer = 0;
		return gNumberVer;
	}

	HANDLE hKey = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING KeyPath = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING SourceKeyName = RTL_CONSTANT_STRING(L"ReleaseId");

	PKEY_VALUE_PARTIAL_INFORMATION AcKeyInfo = NULL;
	KEY_VALUE_PARTIAL_INFORMATION KeyInfo;
	ULONG Length = 0;

	InitializeObjectAttributes(
		&ObjectAttributes,
		&KeyPath,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	Status = ZwOpenKey(&hKey, KEY_READ | KEY_WRITE, &ObjectAttributes);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("Open the Key Handle Faild!! -- %#X\n", Status);
		return 0;
	}

	Status = ZwQueryValueKey(
		hKey,
		&SourceKeyName,
		KeyValuePartialInformation,
		&KeyInfo,
		sizeof(KEY_VALUE_PARTIAL_INFORMATION),
		&Length);

	if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL)
	{
		DbgPrint("读取SystemRoot键值失败!! - %#X\n", Status);
		ZwClose(hKey);
		return 0;
	}


	AcKeyInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, Length, 'tag2');
	if (NULL == AcKeyInfo)
	{
		DbgPrint("在分配保存Key键值的内存空间时失败!!");
		ZwClose(hKey);
		return 0;
	}

	//再次读取注册表键值
	Status = ZwQueryValueKey(
		hKey,
		&SourceKeyName,
		KeyValuePartialInformation,
		AcKeyInfo,
		Length,
		&Length);

	ULONG number = 0;
	if (NT_SUCCESS(Status))
	{

		UNICODE_STRING str = { 0 };
		WCHAR buffer[1024] = { 0 };
		memcpy(buffer, AcKeyInfo->Data, AcKeyInfo->DataLength);
		RtlInitUnicodeString(&str, buffer);
		RtlUnicodeStringToInteger(&str, 0, &number);
	}
	else
	{
		DbgPrint("读取SystemRoot键值失败!! - %#X\n", Status);
	}

	gNumberVer = number;

	ZwClose(hKey);
	ExFreePool(AcKeyInfo);
	return number;
}