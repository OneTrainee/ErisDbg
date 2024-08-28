#include <ntifs.h>
#include <ntddk.h>
#include "PageHook.h"
#include "Log.h"
#include "NtFunction.h"
#include "Performance.h"
#include "RebuiltDbgSystem/initDbg.h"
VOID DriverUnload(PDRIVER_OBJECT pDriverObject);

NTSTATUS LoadVT();
VOID UnloadVT();


typedef NTSTATUS(NTAPI* pfn_NtOpenProcess) (PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
pfn_NtOpenProcess auxiliary_Function;

EXTERN_C NTSTATUS NTAPI MyOpenProcess(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
)
{
	DbgPrintEx(77, 0, "[db]:MyOpenProcess\r\n");
	// DbgBreakPoint();

	return auxiliary_Function(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

	return STATUS_SUCCESS;
}

typedef NTSTATUS(NTAPI* pfn_NtSetInformationThread)(
	HANDLE          ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID           ThreadInformation,
	ULONG           ThreadInformationLength
	);

pfn_NtSetInformationThread auxiliary_NtSetInformationThread;

NTSTATUS MyNtSetInformationThread(
	HANDLE          ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID           ThreadInformation,
	ULONG           ThreadInformationLength
) {

	if (ThreadInformationClass == ThreadHideFromDebugger) {
		DbgPrintEx(77, 0, "[db]:MyNtSetInformationThread ThreadHideFromDebugger\r\n");
		return STATUS_SUCCESS;
	}

	return auxiliary_NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {

	// DbgBreakPoint();
	pDriverObject->DriverUnload = DriverUnload;

	// 
	static const wchar_t kLogFilePath[] = L"\\SystemRoot\\NyxDbg.log";
	static const auto kLogLevel = kLogPutLevelInfo | kLogOptDisableFunctionName;
	auto status = STATUS_UNSUCCESSFUL;
	bool need_reinitialization = false;
	status = LogInitialization(kLogLevel, kLogFilePath);
	if (status == STATUS_REINITIALIZATION_NEEDED) {
		need_reinitialization = true;
	}
	else if (!NT_SUCCESS(status)) {
		return status;
	}

	// 
	status = PerfInitialization();
	if (!NT_SUCCESS(status)) {
		LogTermination();
		return status;
	}
	
	//
	status = InitKernelInfoByOsVersion();
	if (!NT_SUCCESS(status)) {
		LogTermination();
		PerfTermination();
		return status;
	}

	//
	status = LoadVT();

	InitDBG();

	auxiliary_NtSetInformationThread = NtSetInformationThread;
	EptPageHook3(NtSetInformationThread, reinterpret_cast<PVOID*>(&auxiliary_NtSetInformationThread), MyNtSetInformationThread);
	//auxiliary_Function = NtOpenProcess;
	//// EptPageHook2(NtOpenProcess,reinterpret_cast<PVOID *>(&auxiliary_Function), MyOpenProcess);
	//EptPageHook3(NtOpenProcess, reinterpret_cast<PVOID*>(&auxiliary_Function), MyOpenProcess);

	if (!NT_SUCCESS(status)) {
		LogTermination();
		PerfTermination();
		return status;
	}

	// 
	if (need_reinitialization) {
		LogRegisterReinitialization(pDriverObject);
	}

	return status;
}


VOID DriverUnload(PDRIVER_OBJECT pDriverObject) {
	UNREFERENCED_PARAMETER(pDriverObject);
	UnloadVT();
	PerfTermination();
	LogTermination();
}