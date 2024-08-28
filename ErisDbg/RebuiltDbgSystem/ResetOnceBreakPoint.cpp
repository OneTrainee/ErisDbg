
#include "Module.h"
#include <ntimage.h>
#include "Struct.h"
#include "SearchCode.h"

EXTERN_C PPEB32 PsGetProcessWow64Process(PEPROCESS eprocess);

NTSTATUS NTAPI NtProtectVirtualMemory(
	__in HANDLE ProcessHandle,
	__inout PVOID* BaseAddress,
	__inout PSIZE_T RegionSize,
	__in ULONG NewProtect,
	__out PULONG OldProtect
)
{

	typedef NTSTATUS(NTAPI* ZwProtectVirtualMemoryProc)(
		__in HANDLE ProcessHandle,
		__inout PVOID* BaseAddress,
		__inout PSIZE_T RegionSize,
		__in ULONG NewProtect,
		__out PULONG OldProtect
		);

	static ZwProtectVirtualMemoryProc ZwProtectVirtualMemoryFunc = NULL;
	if (!ZwProtectVirtualMemoryFunc)
	{
		UNICODE_STRING uNname = { 0 };
		RtlInitUnicodeString(&uNname, L"ZwIsProcessInJob");
		PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&uNname);

		if (func)
		{
			func += 20;
			for (int i = 0; i < 0x100; i++)
			{
				if (func[i] == 0x48 && func[i + 1] == 0x8b && func[i + 2] == 0xc4)
				{
					ZwProtectVirtualMemoryFunc = (ZwProtectVirtualMemoryProc)(func + i);
					break;
				}
			}
		}


	}

	if (ZwProtectVirtualMemoryFunc)
	{
		return ZwProtectVirtualMemoryFunc(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
	}

	return STATUS_NOT_IMPLEMENTED;
}

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(unsigned __int64 *)(name)
#define DEREF_32( name )*(unsigned long *)(name)
#define DEREF_16( name )*(unsigned short *)(name)
#define DEREF_8( name )*(UCHAR *)(name)
ULONG_PTR GetProcAddressR(ULONG_PTR hModule, const char* lpProcName, BOOLEAN x64Module)
{
	UINT_PTR uiLibraryAddress = 0;
	ULONG_PTR fpResult = NULL;

	if (hModule == NULL)
		return NULL;

	// a module handle is really its base address
	uiLibraryAddress = (UINT_PTR)hModule;

	__try
	{
		UINT_PTR uiAddressArray = 0;
		UINT_PTR uiNameArray = 0;
		UINT_PTR uiNameOrdinals = 0;
		PIMAGE_NT_HEADERS32 pNtHeaders32 = NULL;
		PIMAGE_NT_HEADERS64 pNtHeaders64 = NULL;
		PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
		PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

		// get the VA of the modules NT Header
		pNtHeaders32 = (PIMAGE_NT_HEADERS32)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
		pNtHeaders64 = (PIMAGE_NT_HEADERS64)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
		if (x64Module)
		{
			pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		}
		else
		{
			pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		}


		// get the VA of the export directory
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

		// get the VA for the array of addresses
		uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);

		// get the VA for the array of name pointers
		uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);

		// get the VA for the array of name ordinals
		uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

		// test if we are importing by name or by ordinal...
		if ((PtrToUlong(lpProcName) & 0xFFFF0000) == 0x00000000)
		{
			// import by ordinal...

			// use the import ordinal (- export ordinal base) as an index into the array of addresses
			uiAddressArray += ((IMAGE_ORDINAL(PtrToUlong(lpProcName)) - pExportDirectory->Base) * sizeof(unsigned long));

			// resolve the address for this imported function
			fpResult = (ULONG_PTR)(uiLibraryAddress + DEREF_32(uiAddressArray));
		}
		else
		{
			// import by name...
			unsigned long dwCounter = pExportDirectory->NumberOfNames;
			while (dwCounter--)
			{
				char* cpExportedFunctionName = (char*)(uiLibraryAddress + DEREF_32(uiNameArray));

				// test if we have a match...
				if (strcmp(cpExportedFunctionName, lpProcName) == 0)
				{
					// use the functions name ordinal as an index into the array of name pointers
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(unsigned long));

					// calculate the virtual address for the function
					fpResult = (ULONG_PTR)(uiLibraryAddress + DEREF_32(uiAddressArray));

					// finish...
					break;
				}

				// get the next exported function name
				uiNameArray += sizeof(unsigned long);

				// get the next exported function name ordinal
				uiNameOrdinals += sizeof(unsigned short);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		fpResult = NULL;
	}

	return fpResult;
}

VOID ResetBreakPoint(PEPROCESS Process)
{
	// DbgBreakPoint();
	ULONG_PTR ntdllModule = GetModuleR3(PsGetProcessId(Process), "ntdll.dll", NULL);

	BOOLEAN isX64 = PsGetProcessWow64Process(Process) == NULL;

	ULONG_PTR DbgUiIssueRemoteBreakin = GetProcAddressR(ntdllModule, "DbgUiIssueRemoteBreakin", isX64);

	ULONG_PTR DbgBreakPointInt3 = GetProcAddressR(ntdllModule, "DbgBreakPoint", isX64);

	RTL_OSVERSIONINFOW version = { 0 };

	RtlGetVersion(&version);

	KAPC_STATE kApcState = { 0 };


	KeStackAttachProcess(Process, &kApcState);
	do
	{
		SIZE_T rsize = 0x200;
		PVOID BaseAddress = (PVOID)DbgUiIssueRemoteBreakin;
		ULONG pro = 0;
		NTSTATUS st = NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &rsize, PAGE_EXECUTE_READWRITE, &pro);

		if (NT_SUCCESS(st))
		{

			if (version.dwBuildNumber == 7600 || version.dwBuildNumber == 7601)
			{
				if (isX64)
				{

					ULONG_PTR result = SearchCode("48******4989**4983***49C7", DbgUiIssueRemoteBreakin, 200);
					if (result)
					{
						ULONG_PTR nextAddr = (result + 7);
						//nextAddr+offset = Ŀ�ĵ�ַ  Ŀ�ĵ�ַ- nextAddr = offset
						LONG offset = DbgBreakPointInt3 - nextAddr;

						*(PULONG)(result + 3) = offset;
					}

				}
				else
				{
					ULONG_PTR result = SearchCode("68****5668****56566A*56FF75*E8", DbgUiIssueRemoteBreakin, 200);
					if (result)
					{
						*(PULONG)(result + 1) = DbgBreakPointInt3;
					}
				}
			}
			else
			{
				//WIN10 �Լ���չ
				// Win10 1909�汾��
				if (isX64)
				{
					
					ULONG_PTR result = SearchCode("48******4983***458D**4989**49C7******4983***E8****8BD8", DbgUiIssueRemoteBreakin, 200);
												 
					if (result)
					{
						ULONG_PTR nextAddr = (result + 7);
						//nextAddr+offset = Ŀ�ĵ�ַ  Ŀ�ĵ�ַ- nextAddr = offset
						LONG offset = DbgBreakPointInt3 - nextAddr;

						*(PULONG)(result + 3) = offset;
					}

				}
				else
				{
					ULONG_PTR result = SearchCode("68****518B4D*68****50506A*E8****8BF0", DbgUiIssueRemoteBreakin, 200);
					if (result)
					{
						*(PULONG)(result + 1) = DbgBreakPointInt3;
					}
				}
			}
		}

		st = NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &rsize, pro, &pro);


	} while (0);

	KeUnstackDetachProcess(&kApcState);



}