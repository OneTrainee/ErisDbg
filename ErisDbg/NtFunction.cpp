#include <ntifs.h>
#include <ntddk.h>
#include "Log.h"
#include "SearchCode.h"
#include "NtFunction.h"



typedef NTSTATUS(*PsResumeThreadProc)(IN PETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL);
typedef NTSTATUS(*PsSuspendThreadProc)(IN PETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL);
typedef PETHREAD(NTAPI* PsGetNextProcessThreadProc)(
	IN PEPROCESS Process,
	IN PETHREAD Thread);

typedef PSYSTEM_DLL_ENTRY(*PsQuerySystemDllInfoProc)(ULONG index);

typedef VOID(*PsThawProcessProc)(PEPROCESS eprocess, BOOLEAN a2);
typedef VOID(*KeLeaveCriticalRegionThreadProc)(PETHREAD ethread);
typedef BOOLEAN(*PsFreezeProcessProc)(PEPROCESS eprocess, BOOLEAN a2);
typedef VOID(*KeFreezeAllThreadsProc)(VOID);
typedef VOID(*KeThawAllThreadsProc)(VOID);
typedef VOID(*PsSynchronizeWithThreadInsertionProc)(PETHREAD thread, PETHREAD curThread);
typedef NTSTATUS(*DbgkpSendErrorMessageProc)(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN ULONG Falge,
	IN PVOID	DbgApiMsg);

typedef NTSTATUS(*DbgkpSendApiMessageLpcProc)(
	IN OUT PVOID ApiMsg,
	IN PVOID Port,
	IN BOOLEAN SuspendProcess
	);
typedef PVOID(*ObFastReferenceObjectProc)(IN PEX_FAST_REF FastRef);

typedef NTSTATUS(*ObDuplicateObjectProc)(
	IN PEPROCESS SourceProcess,
	IN HANDLE SourceHandle,
	IN PEPROCESS TargetProcess OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options,
	IN KPROCESSOR_MODE PreviousMode
	);

typedef NTSTATUS(*MmGetFileNameForAddressProc)(
	IN PVOID ProcessVa,
	OUT PUNICODE_STRING FileName
	);

typedef NTSTATUS(*DbgkpPostModuleMessagesProcs)(
	IN PEPROCESS Process,
	IN PETHREAD Thread,
	IN PVOID DebugObject);

struct NtFunction {
	ObDuplicateObjectProc ObDuplicateObjectFunc;
	PsSynchronizeWithThreadInsertionProc PsSynchronizeWithThreadInsertionFunc;
	PsSuspendThreadProc PsSuspendThreadFunc;
	PsGetNextProcessThreadProc PsGetNextProcessThreadFunc;
	PsResumeThreadProc				PsResumeThreadFunc;
	PsQuerySystemDllInfoProc		PsQuerySystemDllInfoFunc;
	PsFreezeProcessProc				PsFreezeProcessFunc;
	KeLeaveCriticalRegionThreadProc KeLeaveCriticalRegionThreadFunc;
	PsThawProcessProc				PsThawProcessFunc;
	MmGetFileNameForAddressProc		MmGetFileNameForAddressFunc;
	DbgkpSendApiMessageLpcProc		DbgkpSendApiMessageLpcFunc;
	DbgkpSendErrorMessageProc	 DbgkpSendErrorMessageFunc;

	ULONG64 NtCreateDebugObject;
	ULONG64 NtWaitForDebugEvent;
	ULONG64 NtDebugActiveProcess;
	ULONG64 NtDebugContinue;
	ULONG64 DbgkForwardException;
};

struct NtFunction g_NtFunction;

struct NtSymbolOffset g_NtSymbolOffset;

typedef struct _FunctionSignatureItem {
	ULONG64 funcAddr;
	CONST PCHAR name;
	CONST ULONG64 offset;
	CONST PCHAR signatrue;
}FunctionSignatureItem, * PFunctionSignatureItem;


ULONG64 SearchFunctionItem(FunctionSignatureItem functionTable[], CONST PCHAR functionName) {

	auto index = 0;
	BOOLEAN bFind = FALSE;
	for (; functionTable[index].offset != 0xffff; index++) {
		if (strcmp(functionName, functionTable[index].name) == 0) {
			bFind = TRUE;
			break;
		}
	}

	if (!bFind) {
		return 0;
	}

	const auto signatrue = functionTable[index].signatrue;
	const auto offset = functionTable[index].offset;

	functionTable[index].funcAddr = SearchNtCodeHead(signatrue, offset);
	return functionTable[index].funcAddr;
}

BOOLEAN Init_g_NtFunction(const char* version, FunctionSignatureItem functionTable[]) {

	g_NtFunction.ObDuplicateObjectFunc = (ObDuplicateObjectProc)SearchFunctionItem(functionTable,"ObDuplicateObject");
	g_NtFunction.PsSynchronizeWithThreadInsertionFunc = (PsSynchronizeWithThreadInsertionProc)SearchFunctionItem(functionTable, "PsSynchronizeWithThreadInsertion");
	g_NtFunction.PsSuspendThreadFunc = (PsSuspendThreadProc)SearchFunctionItem(functionTable, "PsSuspendThread");
	g_NtFunction.PsGetNextProcessThreadFunc = (PsGetNextProcessThreadProc)SearchFunctionItem(functionTable, "PsGetNextProcessThread");
	g_NtFunction.PsResumeThreadFunc = (PsResumeThreadProc)SearchFunctionItem(functionTable, "PsResumeThread");
	g_NtFunction.PsQuerySystemDllInfoFunc			=	(PsQuerySystemDllInfoProc		)SearchFunctionItem(functionTable,"PsQuerySystemDllInfo");
	g_NtFunction.PsFreezeProcessFunc				=	(PsFreezeProcessProc			)SearchFunctionItem(functionTable,"PsFreezeProcess");	
	g_NtFunction.KeLeaveCriticalRegionThreadFunc	=	(KeLeaveCriticalRegionThreadProc)SearchFunctionItem(functionTable,"KeLeaveCriticalRegionThread"); 
	g_NtFunction.PsThawProcessFunc					=	(PsThawProcessProc				)SearchFunctionItem(functionTable,"PsThawProcess");
	g_NtFunction.MmGetFileNameForAddressFunc		=	(MmGetFileNameForAddressProc	)SearchFunctionItem(functionTable,"MmGetFileNameForAddress");	
	g_NtFunction.DbgkpSendApiMessageLpcFunc			=	(DbgkpSendApiMessageLpcProc		)SearchFunctionItem(functionTable,"DbgkpSendApiMessageLpc");
	g_NtFunction.DbgkpSendErrorMessageFunc			=	(DbgkpSendErrorMessageProc		)SearchFunctionItem(functionTable,"DbgkpSendErrorMessage");


	
	g_NtFunction.NtCreateDebugObject  =	SearchFunctionItem(functionTable, "NtCreateDebugObject");
	g_NtFunction.NtWaitForDebugEvent  =	SearchFunctionItem(functionTable, "NtWaitForDebugEvent");
	g_NtFunction.NtDebugActiveProcess = SearchFunctionItem(functionTable, "NtDebugActiveProcess");
	g_NtFunction.NtDebugContinue      =	SearchFunctionItem(functionTable, "NtDebugContinue");
	g_NtFunction.DbgkForwardException = SearchFunctionItem(functionTable, "DbgkForwardException");

	for (auto i = 0; functionTable[i].offset != 0xffff; i++) {
		const auto&item = functionTable[i];
		if (item.funcAddr) {
			HYPERPLATFORM_LOG_INFO("%s - %llx - %s ",version, item.funcAddr, item.name );
		}
		else {
			HYPERPLATFORM_LOG_ERROR("%s - %llx - %s ", version, item.funcAddr, item.name);
			return FALSE;
		}
	}
	return TRUE;
}

#include "WinOsVersion/Win10_18363.hpp"
#include "WinOsVersion/Win10_19045.hpp"

BOOLEAN InitNtFunctionAndNtSymbolOffsetByOsVersion() {

	RTL_OSVERSIONINFOW osVersionInfo;
	NTSTATUS status;

	RtlZeroMemory(&osVersionInfo, sizeof(RTL_OSVERSIONINFOW));
	osVersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

	status = RtlGetVersion(&osVersionInfo);
	if (!NT_SUCCESS(status)) {
		HYPERPLATFORM_LOG_ERROR("Failed to Get OS Version!");
		return FALSE;
	}
	HYPERPLATFORM_LOG_INFO("OS Version: %d.%d.%d", osVersionInfo.dwMajorVersion, osVersionInfo.dwMinorVersion, osVersionInfo.dwBuildNumber);
	BOOLEAN bSuccess = FALSE;
	if (osVersionInfo.dwMajorVersion == 10) {
		if (osVersionInfo.dwBuildNumber == 18363) {
			Init_g_SymbolOffset_Win10_18363();
			bSuccess = Init_g_NtFunction("10.0.18363",functionTable_Win10_18363);
		}
		else if (osVersionInfo.dwBuildNumber == 19045) {
			Init_g_SymbolOffset_Win10_19045();
			bSuccess = Init_g_NtFunction("10.0.19045", functionTable_Win10_19045);
		}
	}
	if (!bSuccess) {
		HYPERPLATFORM_LOG_ERROR("Fail to init Nt function and Nt symbol offset!");
	}
	return bSuccess;
}

NTSTATUS InitKernelInfoByOsVersion() {
	
	BOOLEAN bSuccess = InitNtFunctionAndNtSymbolOffsetByOsVersion();
	
	if (bSuccess) {
		return STATUS_SUCCESS;
	}

	return STATUS_UNSUCCESSFUL;
}

ULONG64 NtCreateDebugObjectFuncAddr()
{
	return g_NtFunction.NtCreateDebugObject;
}

ULONG64 NtWaitForDebugEventFuncAddr()
{
	return g_NtFunction.NtWaitForDebugEvent;
}

ULONG64 NtDebugActiveProcessFuncAddr()
{
	
	return g_NtFunction.NtDebugActiveProcess;
}

ULONG64 NtDebugContinueFuncAddr()
{
	return g_NtFunction.NtDebugContinue;
}

ULONG64 NtDbgkForwardExceptionFuncAddr()
{
	return g_NtFunction.DbgkForwardException;
}

// -------------------------


NTSTATUS ObDuplicateObject(
	IN PEPROCESS SourceProcess,
	IN HANDLE SourceHandle,
	IN PEPROCESS TargetProcess OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options,
	IN KPROCESSOR_MODE PreviousMode
)
{
	return g_NtFunction.ObDuplicateObjectFunc(SourceProcess, SourceHandle,
		TargetProcess,
		TargetHandle,
		DesiredAccess,
		HandleAttributes,
		Options,
		PreviousMode);

	return STATUS_SUCCESS;
}



VOID PsSynchronizeWithThreadInsertion(PETHREAD thread, PETHREAD curThread)
{
	g_NtFunction.PsSynchronizeWithThreadInsertionFunc(thread, curThread);
}

NTSTATUS PsSuspendThread(IN PETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL)
{
	return g_NtFunction.PsSuspendThreadFunc(Thread, PreviousSuspendCount);
}


PETHREAD PsGetNextProcessThread(PEPROCESS Process, PETHREAD Thread)
{
	return g_NtFunction.PsGetNextProcessThreadFunc(Process, Thread);
}

NTSTATUS PsResumeThread(IN PETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL)
{
	return g_NtFunction.PsResumeThreadFunc(Thread, PreviousSuspendCount);
}

PSYSTEM_DLL_ENTRY PsQuerySystemDllInfo(ULONG index)
{
	return g_NtFunction.PsQuerySystemDllInfoFunc(index);
}

BOOLEAN PsFreezeProcess(PEPROCESS eprocess, BOOLEAN a2) {

	return g_NtFunction.PsFreezeProcessFunc(eprocess, a2);
}

VOID KeLeaveCriticalRegionThread(PETHREAD ethread) {
	g_NtFunction.KeLeaveCriticalRegionThreadFunc(ethread);
}

VOID PsThawProcess(PEPROCESS eprocess, BOOLEAN a2) {
	g_NtFunction.PsThawProcessFunc(eprocess, a2);
}

NTSTATUS MmGetFileNameForAddress(
	IN PVOID ProcessVa,
	OUT PUNICODE_STRING FileName
)
{
	return g_NtFunction.MmGetFileNameForAddressFunc(ProcessVa, FileName);
}

NTSTATUS DbgkpSendApiMessageLpc(
	IN OUT PVOID ApiMsg,
	IN PVOID Port,
	IN BOOLEAN SuspendProcess
)
{
	return g_NtFunction.DbgkpSendApiMessageLpcFunc(ApiMsg, Port, SuspendProcess);
}

NTSTATUS DbgkpSendErrorMessage(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN ULONG Falge,
	IN PVOID	DbgApiMsg)
{
	return g_NtFunction.DbgkpSendErrorMessageFunc(ExceptionRecord, Falge, DbgApiMsg);
}
