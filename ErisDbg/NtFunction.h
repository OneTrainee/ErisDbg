#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include "RebuiltDbgSystem/Struct.h"

typedef struct _SYSTEM_DLL_ENTRY
{
	ULONG64 type;
	UNICODE_STRING FullName;
	PVOID ImageBase;
	PWCHAR BaseName;
	PWCHAR StaticUnicodeBuffer;
}SYSTEM_DLL_ENTRY, * PSYSTEM_DLL_ENTRY;

NTSTATUS ObDuplicateObject(
	IN PEPROCESS SourceProcess,
	IN HANDLE SourceHandle,
	IN PEPROCESS TargetProcess OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options,
	IN KPROCESSOR_MODE PreviousMode
);

PETHREAD PsGetNextProcessThread(PEPROCESS Process, PETHREAD Thread);

VOID PsSynchronizeWithThreadInsertion(PETHREAD thread, PETHREAD curThread);

NTSTATUS PsSuspendThread(IN PETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL);

NTSTATUS PsResumeThread(IN PETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL);

PSYSTEM_DLL_ENTRY PsQuerySystemDllInfo(ULONG index);

BOOLEAN PsFreezeProcess(PEPROCESS eprocess, BOOLEAN a2);

VOID KeLeaveCriticalRegionThread(PETHREAD ethread);

VOID PsThawProcess(PEPROCESS eprocess, BOOLEAN a2);

NTSTATUS MmGetFileNameForAddress(IN PVOID ProcessVa, OUT PUNICODE_STRING FileName);

NTSTATUS DbgkpSendApiMessageLpc(IN OUT PVOID ApiMsg, IN PVOID Port, IN BOOLEAN SuspendProcess);

NTSTATUS DbgkpSendErrorMessage(IN PEXCEPTION_RECORD ExceptionRecord, IN ULONG Falge, IN PVOID	DbgApiMsg);

struct NtSymbolOffset {
	// EPROCESS
	ULONG64 EPROCESS_ProcessLock;
	ULONG64 EPROCESS_RundownProtect;
	ULONG64 EPROCESS_Flags;
	ULONG64 EPROCESS_DebugPort;
	ULONG64 EPROCESS_ExceptionPortData;
	// ETHREAD
	ULONG64 ETHREAD_Teb;
	ULONG64 ETHREAD_MiscFlags;
	ULONG64 ETHREAD_ApcState_Process;
	ULONG64 ETHREAD_KernelApcDisable;
	ULONG64 ETHREAD_ApcStateIndex;
	ULONG64 ETHREAD_StartAddress;
	ULONG64 ETHREAD_RundownProtect;
	ULONG64 ETHREAD_CrossThreadFlags;
};

extern struct NtSymbolOffset g_NtSymbolOffset;

NTSTATUS InitKernelInfoByOsVersion();

ULONG64 NtCreateDebugObjectFuncAddr();

ULONG64 NtWaitForDebugEventFuncAddr();

ULONG64 NtDebugActiveProcessFuncAddr();

ULONG64 NtDebugContinueFuncAddr();

ULONG64 NtDbgkForwardExceptionFuncAddr();