#include "Dbgkp.h"
#include "Struct.h"
#include "dbg.h"
#include "peb.h"
#include "export.h"
#include "ResetOnceBreakPoint.h"
#include <ntimage.h>

#include "..\NtFunction.h"


FAST_MUTEX DbgkpProcessDebugPortMutex;
POBJECT_TYPE g_HotGeDebugObject;
LONG g_DbgkpMaxModuleMsgs;

VOID DbgkpConvertKernelToUserStateChange(PDBGUI_WAIT_STATE_CHANGE WaitStateChange, PDEBUG_EVENT DebugEvent)
{
	WaitStateChange->AppClientId = DebugEvent->ClientId;
	switch (DebugEvent->ApiMsg.ApiNumber) {
	case DbgKmExceptionApi:
		switch (DebugEvent->ApiMsg.u.Exception.ExceptionRecord.ExceptionCode) {
		case STATUS_BREAKPOINT:
			WaitStateChange->NewState = DbgBreakpointStateChange;
			break;

		case STATUS_SINGLE_STEP:
			WaitStateChange->NewState = DbgSingleStepStateChange;
			break;

		default:
			WaitStateChange->NewState = DbgExceptionStateChange;
			break;
		}
		WaitStateChange->StateInfo.Exception = DebugEvent->ApiMsg.u.Exception;
		break;

	case DbgKmCreateThreadApi:
		WaitStateChange->NewState = DbgCreateThreadStateChange;
		WaitStateChange->StateInfo.CreateThread.NewThread = DebugEvent->ApiMsg.u.CreateThread;
		break;

	case DbgKmCreateProcessApi:
		WaitStateChange->NewState = DbgCreateProcessStateChange;
		WaitStateChange->StateInfo.CreateProcessInfo.NewProcess = DebugEvent->ApiMsg.u.CreateProcessInfo;
		DebugEvent->ApiMsg.u.CreateProcessInfo.FileHandle = NULL;
		break;

	case DbgKmExitThreadApi:
		WaitStateChange->NewState = DbgExitThreadStateChange;
		WaitStateChange->StateInfo.ExitThread = DebugEvent->ApiMsg.u.ExitThread;
		break;

	case DbgKmExitProcessApi:
		WaitStateChange->NewState = DbgExitProcessStateChange;
		WaitStateChange->StateInfo.ExitProcess = DebugEvent->ApiMsg.u.ExitProcess;
		break;

	case DbgKmLoadDllApi:
		WaitStateChange->NewState = DbgLoadDllStateChange;
		WaitStateChange->StateInfo.LoadDll = DebugEvent->ApiMsg.u.LoadDll;
		DebugEvent->ApiMsg.u.LoadDll.FileHandle = NULL;
		break;

	case DbgKmUnloadDllApi:
		WaitStateChange->NewState = DbgUnloadDllStateChange;
		WaitStateChange->StateInfo.UnloadDll = DebugEvent->ApiMsg.u.UnloadDll;
		break;

	default:
		ASSERT(FALSE);
	}
}

VOID DbgkpOpenHandles(PDBGUI_WAIT_STATE_CHANGE WaitStateChange, PEPROCESS Process, PETHREAD Thread)
{
	NTSTATUS Status;
	PEPROCESS CurrentProcess;
	HANDLE OldHandle;

	switch (WaitStateChange->NewState) {
	case DbgCreateThreadStateChange:
		Status = ObOpenObjectByPointer(Thread,
			0,
			NULL,
			THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | \
			THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION | THREAD_TERMINATE |
			READ_CONTROL | SYNCHRONIZE,
			*PsThreadType,
			KernelMode,
			&WaitStateChange->StateInfo.CreateThread.HandleToThread);
		if (!NT_SUCCESS(Status)) {
			WaitStateChange->StateInfo.CreateThread.HandleToThread = NULL;
		}
		break;

	case DbgCreateProcessStateChange:

		Status = ObOpenObjectByPointer(Thread,
			0,
			NULL,
			THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | \
			THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION | THREAD_TERMINATE |
			READ_CONTROL | SYNCHRONIZE,
			*PsThreadType,
			KernelMode,
			&WaitStateChange->StateInfo.CreateProcessInfo.HandleToThread);
		if (!NT_SUCCESS(Status)) {
			WaitStateChange->StateInfo.CreateProcessInfo.HandleToThread = NULL;
		}
		Status = ObOpenObjectByPointer(Process,
			0,
			NULL,
			PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
			PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION |
			PROCESS_CREATE_THREAD | PROCESS_TERMINATE |
			READ_CONTROL | SYNCHRONIZE,
			*PsProcessType,
			KernelMode,
			&WaitStateChange->StateInfo.CreateProcessInfo.HandleToProcess);
		if (!NT_SUCCESS(Status)) {
			WaitStateChange->StateInfo.CreateProcessInfo.HandleToProcess = NULL;
		}

		OldHandle = WaitStateChange->StateInfo.CreateProcessInfo.NewProcess.FileHandle;
		if (OldHandle != NULL) {
			CurrentProcess = (PEPROCESS)PsGetCurrentProcess();
			Status = ObDuplicateObject((PEPROCESS)CurrentProcess,
				OldHandle,
				(PEPROCESS)CurrentProcess,
				&WaitStateChange->StateInfo.CreateProcessInfo.NewProcess.FileHandle,
				0,
				0,
				DUPLICATE_SAME_ACCESS,
				KernelMode);
			if (!NT_SUCCESS(Status)) {
				WaitStateChange->StateInfo.CreateProcessInfo.NewProcess.FileHandle = NULL;
			}
			if (Status != STATUS_INVALID_HANDLE)
			{
				ObCloseHandle(OldHandle, KernelMode);
			}
		}
		break;

	case DbgLoadDllStateChange:

		//DbgBreakPoint();
		OldHandle = WaitStateChange->StateInfo.LoadDll.FileHandle;
		if (OldHandle != NULL) {
			CurrentProcess = (PEPROCESS)PsGetCurrentProcess();
			Status = ObDuplicateObject((PEPROCESS)CurrentProcess,
				OldHandle,
				(PEPROCESS)CurrentProcess,
				&WaitStateChange->StateInfo.LoadDll.FileHandle,
				0,
				0,
				DUPLICATE_SAME_ACCESS,
				KernelMode);
			if (!NT_SUCCESS(Status)) {
				WaitStateChange->StateInfo.LoadDll.FileHandle = NULL;
			}

			if (Status != STATUS_INVALID_HANDLE)
			{
				ObCloseHandle(OldHandle, KernelMode);
			}

		}

		break;

	default:
		break;
	}
}


BOOLEAN EntryAcquireRundownProtectionByProcess(PEPROCESS eprocess)
{
		/*
			// PEPROCESSWIN7 eprocessWin7 = (PEPROCESSWIN7)(eprocess);
		*/
		return ExAcquireRundownProtection((PEX_RUNDOWN_REF)((PUCHAR)eprocess + g_NtSymbolOffset.EPROCESS_RundownProtect));

}

VOID ExitReleaseRundownProtectionByProcess(PEPROCESS eprocess)
{
	ExReleaseRundownProtection((PEX_RUNDOWN_REF)((PUCHAR)eprocess + g_NtSymbolOffset.EPROCESS_RundownProtect));
}

VOID ExitReleaseRundownProtectionByThread(PETHREAD thread)
{
	ExReleaseRundownProtection((PEX_RUNDOWN_REF)((PUCHAR)thread + g_NtSymbolOffset.ETHREAD_RundownProtect));
}

BOOLEAN EntryAcquireRundownProtectionByThread(PETHREAD thread)
{

	return ExAcquireRundownProtection((PEX_RUNDOWN_REF)((PUCHAR)thread + g_NtSymbolOffset.ETHREAD_RundownProtect));
}

BOOLEAN IsThreadSystem(PETHREAD thread)
{
	ULONG32 MiscFlags  = *(PULONG32)((PUCHAR)thread + g_NtSymbolOffset.ETHREAD_MiscFlags);
	return (MiscFlags >> 0xD) & 1;
}

BOOLEAN IsThreadInserted(PETHREAD thread)
{
	ULONG32 CrossThreadFlags = *(PULONG32)((PUCHAR)thread + g_NtSymbolOffset.ETHREAD_CrossThreadFlags);
	return (CrossThreadFlags >> 1) & 1;
}

PVOID PsGetThreadStartAddress(PETHREAD thread)
{
	PVOID StartAddress = *(PVOID*)((PUCHAR)thread + g_NtSymbolOffset.ETHREAD_StartAddress);
	return StartAddress;
}

PVOID GetSectionObject(PEPROCESS Process)
{
	UNICODE_STRING uni = { 0 };

	RtlInitUnicodeString(&uni, L"PsGetProcessSectionBaseAddress");
	PUCHAR p = (PUCHAR)MmGetSystemRoutineAddress(&uni);
	ULONG offset = *(PULONG)(p + 3);
	if (offset)
	{
		offset -= 8;
	}
	return (PVOID) * (PULONG64)((ULONG64)Process + offset);
}

NTSTATUS MmGetFileNameForProcess(
	PEPROCESS eprocess,
	OUT POBJECT_NAME_INFORMATION* FileNameInfo
)
{
	ULONG NumberOfBytes;
	ULONG AdditionalLengthNeeded;
	NTSTATUS Status;
	PFILE_OBJECT FileObject;

	NumberOfBytes = 1024;

	*FileNameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(PagedPool, NumberOfBytes, '  mM');

	if (*FileNameInfo == NULL) {
		return STATUS_NO_MEMORY;
	}

	Status = PsReferenceProcessFilePointer(eprocess, (PVOID*)&FileObject);
	if (!NT_SUCCESS(Status))
	{
		return STATUS_NOT_FOUND;
	}


	Status = ObQueryNameString(FileObject,
		*FileNameInfo,
		NumberOfBytes,
		&AdditionalLengthNeeded);

	ObDereferenceObject(FileObject);

	if (!NT_SUCCESS(Status)) {

		if (Status == STATUS_INFO_LENGTH_MISMATCH) {

			ExFreePool(*FileNameInfo);

			NumberOfBytes += AdditionalLengthNeeded;

			*FileNameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(PagedPool, NumberOfBytes, 'mM');

			if (*FileNameInfo == NULL) {
				return STATUS_NO_MEMORY;
			}

			Status = ObQueryNameString(FileObject,
				*FileNameInfo,
				NumberOfBytes,
				&AdditionalLengthNeeded);

			if (NT_SUCCESS(Status)) {
				return STATUS_SUCCESS;
			}
		}

		ExFreePool(*FileNameInfo);
		*FileNameInfo = NULL;
		return Status;
	}

	return Status;
}

PDEBUG_OBJECT HotGePsGetProcessDebugPort(PEPROCESS Process)
{

	return *(PDEBUG_OBJECT*)((PUCHAR)Process + g_NtSymbolOffset.EPROCESS_DebugPort);
	/*
	ULONG offset = *(PULONG)((PUCHAR)PsGetProcessId + 3);
	offset -= 0x10;
	return (PDEBUG_OBJECT )*(PULONG64)((PUCHAR)Process + offset);
	*/
}

VOID HotGePsSetProcessDebugPort(PEPROCESS Process, PDEBUG_OBJECT obj)
{
	/* 
		ULONG offset = *(PULONG)((PUCHAR)PsGetProcessId + 3);
		offset -= 0x10;
		*(PULONG64)((PUCHAR)Process + offset) = obj;
	*/
	*(PDEBUG_OBJECT*)((PUCHAR)Process + g_NtSymbolOffset.EPROCESS_DebugPort) = obj;
}


BOOLEAN IsThreadSkipCreationMsg(PETHREAD thread)
{
	ULONG32 CrossThreadFlags = *(PULONG32)((PUCHAR)thread + g_NtSymbolOffset.ETHREAD_CrossThreadFlags);
	return (CrossThreadFlags >> 7) & 1;
}

VOID SetThreadCrossThreadFlags(PETHREAD thread, ULONG f)
{
	*(PULONG32)((PUCHAR)thread + g_NtSymbolOffset.ETHREAD_CrossThreadFlags) |= f;
}

ULONG SetProcessFlags(PEPROCESS Process, ULONG Flags)
{
	ULONG flags = *(PULONG)((PUCHAR)Process + g_NtSymbolOffset.EPROCESS_Flags);
	*(PULONG)((PUCHAR)Process + g_NtSymbolOffset.EPROCESS_Flags) |= Flags;
	return flags;
}


BOOLEAN IsThreadSkipTerminationMsg(PETHREAD thread)
{
	ULONG32 CrossThreadFlags = *(PULONG32)((PUCHAR)thread + g_NtSymbolOffset.ETHREAD_CrossThreadFlags);
	return (CrossThreadFlags >> 8) & 1;
}

ULONG GetThreadApcIndex(PETHREAD thread)
{
	
	return *(PUCHAR)((PUCHAR)thread + g_NtSymbolOffset.ETHREAD_ApcStateIndex);
}

PTEB GetTEB(PETHREAD thread)
{

	return *(PTEB*)((PUCHAR)thread + g_NtSymbolOffset.ETHREAD_Teb);
}

BOOLEAN DbgkpSuspendProcess(PEPROCESS eprocess)
{
	//PEPROCESS eprocess = PsGetCurrentProcess();

	PETHREAD ethread = PsGetCurrentThread();

	*((USHORT*)((PUCHAR)ethread + g_NtSymbolOffset.ETHREAD_KernelApcDisable)) -= 1;


	if (PsFreezeProcess(eprocess,FALSE)) {
		return TRUE;
	}
	else {
		KeLeaveCriticalRegionThread(ethread);
		return FALSE;
	}
}

VOID DbgkpFreeDebugEvent(IN PDEBUG_EVENT DebugEvent)
{
	NTSTATUS Status;

	switch (DebugEvent->ApiMsg.ApiNumber) {
	case DbgKmCreateProcessApi:
		if (DebugEvent->ApiMsg.u.CreateProcessInfo.FileHandle != NULL) {
			Status = ObCloseHandle(DebugEvent->ApiMsg.u.CreateProcessInfo.FileHandle, KernelMode);
		}
		break;

	case DbgKmLoadDllApi:
		if (DebugEvent->ApiMsg.u.LoadDll.FileHandle != NULL) {
			Status = ObCloseHandle(DebugEvent->ApiMsg.u.LoadDll.FileHandle, KernelMode);
		}
		break;

	}

	ObDereferenceObject(DebugEvent->Process);
	ObDereferenceObject(DebugEvent->Thread);
	ExFreePool(DebugEvent);
}

VOID DbgkpWakeTarget(IN PDEBUG_EVENT DebugEvent)
{
	PETHREAD Thread = DebugEvent->Thread;

	if ((DebugEvent->Flags & DEBUG_EVENT_SUSPEND) != 0) {
		PsResumeThread(DebugEvent->Thread, NULL);
	}

	if (DebugEvent->Flags & DEBUG_EVENT_RELEASE) {
		ExReleaseRundownProtection((PEX_RUNDOWN_REF)((PUCHAR)Thread + g_NtSymbolOffset.ETHREAD_RundownProtect));
	}

	if ((DebugEvent->Flags & DEBUG_EVENT_NOWAIT) == 0) {
		KeSetEvent(&DebugEvent->ContinueEvent, 0, FALSE); // Wake up waiting process
	}
	else {
		DbgkpFreeDebugEvent(DebugEvent);
	}

}



NTSTATUS DbgkpQueueMessage(
	IN PEPROCESS Process,
	IN PETHREAD Thread,
	IN OUT PDBGKM_APIMSG ApiMsg,
	IN ULONG Flags,
	IN PDEBUG_OBJECT TargetDebugObject
)
{
	//DbgBreakPoint();
	PDEBUG_OBJECT pDebugObject = NULL;
	PDEBUG_EVENT pDebugEvent = { 0 };
	DEBUG_EVENT mDebugEvent = { 0 };
	BOOLEAN isThreadSkipCreationMsg = FALSE;
	ULONG mFlags = Flags;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	//PDBGKM_APIMSG SaveApiMsg = NULL;

	if (mFlags & DEBUG_EVENT_NOWAIT)
	{
		pDebugEvent = (PDEBUG_EVENT)ExAllocatePoolWithQuotaTag((POOL_TYPE)POOL_QUOTA_FAIL_INSTEAD_OF_RAISE, sizeof(DEBUG_EVENT), 'EgbD');
		if (!pDebugEvent) return STATUS_INSUFFICIENT_RESOURCES;

		pDebugEvent->Flags = mFlags | DEBUG_EVENT_INACTIVE;

		ObReferenceObject(Process);
		ObReferenceObject(Thread);
		pDebugObject = TargetDebugObject;
		pDebugEvent->BackoutThread = KeGetCurrentThread();
	}
	else
	{
		pDebugEvent = &mDebugEvent;
		mDebugEvent.Flags = mFlags;
		ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);
		DBGKM_APINUMBER apiNumber = ApiMsg->ApiNumber;
		pDebugObject = HotGePsGetProcessDebugPort(Process);

		if ((apiNumber == DbgKmCreateThreadApi || apiNumber == DbgKmCreateProcessApi))
		{
			isThreadSkipCreationMsg = IsThreadSkipCreationMsg(Thread);
			if (isThreadSkipCreationMsg)
			{
				pDebugObject = NULL;
			}
		}

		if ((apiNumber == DbgKmLoadDllApi) && IsThreadSkipCreationMsg(Thread) && (mFlags & 0x40))
		{
			pDebugObject = NULL;
		}

		if ((apiNumber == DbgKmExitThreadApi || apiNumber == DbgKmExitProcessApi) && IsThreadSkipTerminationMsg(Thread))
		{
			pDebugObject = NULL;
		}

		KeInitializeEvent(&mDebugEvent.ContinueEvent, SynchronizationEvent, 0);
	}

	//SaveApiMsg = &pDebugEvent->ApiMsg;
	pDebugEvent->Process = Process;
	pDebugEvent->Thread = Thread;
	memcpy(&pDebugEvent->ApiMsg, ApiMsg, sizeof(DBGKM_APIMSG));
	// pDebugEvent->ClientId = GetThreadClientId(Thread);
	pDebugEvent->ClientId.UniqueProcess = PsGetProcessId(Process);
	pDebugEvent->ClientId.UniqueThread = PsGetThreadId(Thread);
	if (pDebugObject)
	{
		ExAcquireFastMutex(&pDebugObject->Mutex);
		if (pDebugObject->Flags & DEBUG_OBJECT_DELETE_PENDING)
		{
			status = STATUS_DEBUGGER_INACTIVE;
		}
		else
		{
			InsertTailList(&pDebugObject->EventList, &pDebugEvent->EventList);
			if ((mFlags & DEBUG_EVENT_NOWAIT) == 0)
			{
				KeSetEvent(&pDebugObject->EventsPresent, 0, 0);
			}

			status = STATUS_SUCCESS;
		}

		ExReleaseFastMutex(&pDebugObject->Mutex);
		//SaveApiMsg = &pDebugEvent->ApiMsg;
	}
	else
	{
		status = STATUS_PORT_NOT_SET;
	}

	if ((mFlags & DEBUG_EVENT_NOWAIT))
	{
		if (!NT_SUCCESS(status))
		{
			ObDereferenceObject(Process);
			ObDereferenceObject(Thread);
			ExFreePoolWithTag(pDebugEvent, 0);
		}
	}
	else
	{
		ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);
		if (NT_SUCCESS(status))
		{
			KeWaitForSingleObject(&pDebugEvent->ContinueEvent, Executive, KernelMode, FALSE, NULL);
			status = pDebugEvent->Status;
			RtlCopyMemory(ApiMsg, &pDebugEvent->ApiMsg, sizeof(DBGKM_APIMSG));
		}
	}

	return status;
}



NTSTATUS DbgkpSendApiMessage(
	PEPROCESS eprocess,
	ULONG Flags,
	PDBGKM_APIMSG apiMsg
)
{
	BOOLEAN isSuspend = FALSE;
	if (Flags & 1 && eprocess == PsGetCurrentProcess())
	{
		isSuspend = DbgkpSuspendProcess(PsGetCurrentProcess());
	}

	apiMsg->ReturnedStatus = STATUS_PENDING;

	// 2 4 8 16 32 
	ULONG eventFlags = (Flags & DEBUG_EVENT_NOWAIT) << 5; //挂起
	NTSTATUS status = DbgkpQueueMessage(eprocess, PsGetCurrentThread(), apiMsg, eventFlags, NULL);

	if (isSuspend)
	{
		PsThawProcess(eprocess, FALSE);
		KeLeaveCriticalRegion();
	}

	return status;
}

HANDLE DbgkpProcessToFileHandle(
	IN PVOID SectionObject
)
{
	NTSTATUS Status;
	OBJECT_ATTRIBUTES Obja;
	IO_STATUS_BLOCK IoStatusBlock;
	HANDLE Handle;
	POBJECT_NAME_INFORMATION FileNameInfo;

	PAGED_CODE();

	Status = MmGetFileNameForProcess((PEPROCESS)SectionObject, &FileNameInfo);
	if (!NT_SUCCESS(Status)) {
		return NULL;
	}

	InitializeObjectAttributes(
		&Obja,
		&FileNameInfo->Name,
		OBJ_CASE_INSENSITIVE | OBJ_FORCE_ACCESS_CHECK | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);

	Status = ZwOpenFile(
		&Handle,
		(ACCESS_MASK)(GENERIC_READ | SYNCHRONIZE),
		&Obja,
		&IoStatusBlock,
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_SYNCHRONOUS_IO_NONALERT
	);
	ExFreePool(FileNameInfo);
	if (!NT_SUCCESS(Status)) {
		return NULL;
	}
	else {
		return Handle;
	}
}

PEPROCESS PsGetThreadToAPCProcess(PETHREAD thread)
{
	PEPROCESS process = *(PEPROCESS*)((PUCHAR)thread + g_NtSymbolOffset.ETHREAD_ApcState_Process);
	return process;
}


VOID  DbgkSendSystemDllMessages(IN PETHREAD thread, IN PDEBUG_OBJECT TargetDebugObject, DBGKM_APIMSG* apiMsg)
{
	PEPROCESS eprocess = NULL;
	BOOLEAN isAttach = 0;
	KAPC_STATE kApcState = { 0 };
	PTEB teb = NULL;

	if (thread)
	{

		eprocess = PsGetThreadToAPCProcess(thread);
	}
	else
	{
		eprocess = PsGetCurrentProcess();
	}



	PSYSTEM_DLL_ENTRY dllEntry = NULL;
	for (int i = 0; i < 2; i++)
	{
		dllEntry = PsQuerySystemDllInfo(i);

		if (dllEntry && (i != 1 || PsGetProcessWow64Process(eprocess)))
		{
			//这个地方可能有问题
			memset(&apiMsg->u.LoadDll, 0, sizeof(DBGKM_LOAD_DLL));
			PVOID ImageBase = dllEntry->ImageBase;
			apiMsg->u.LoadDll.BaseOfDll = ImageBase;
			if (thread && i)
			{
				isAttach = TRUE;
				KeStackAttachProcess(eprocess, &kApcState);
			}
			else
			{
				isAttach = FALSE;
			}

			PIMAGE_NT_HEADERS pNt = RtlImageNtHeader(ImageBase);
			if (pNt)
			{
				apiMsg->u.LoadDll.DebugInfoFileOffset = pNt->FileHeader.PointerToSymbolTable;
				apiMsg->u.LoadDll.DebugInfoSize = pNt->FileHeader.NumberOfSymbols;
			}

			if (thread)
			{
				teb = NULL;
			}
			else
			{
				PETHREAD CurThread = PsGetCurrentThread();
				if (IsThreadSystem(CurThread) || GetThreadApcIndex(CurThread) == 1)
				{
					teb = NULL;
				}
				else
				{
					teb = GetTEB(CurThread);
				}

				if (teb)
				{
					RtlMoveMemory(teb->StaticUnicodeBuffer, dllEntry->StaticUnicodeBuffer, 0x20A);
					teb->NtTib.ArbitraryUserPointer = teb->StaticUnicodeBuffer;
					apiMsg->u.LoadDll.NamePointer = teb->NtTib.ArbitraryUserPointer;

				}
			}

			if (isAttach)
			{
				KeUnstackDetachProcess(&kApcState);
			}

			OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
			IO_STATUS_BLOCK IoStatusBlock = { 0 };
			InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_FORCE_ACCESS_CHECK | OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

			NTSTATUS status = ZwOpenFile((PHANDLE)&apiMsg->u.LoadDll.FileHandle, GENERIC_READ | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock, FILE_SHARE_VALID_FLAGS, FILE_SYNCHRONOUS_IO_NONALERT);
			if (!NT_SUCCESS(status))
			{
				apiMsg->u.LoadDll.FileHandle = NULL;
			}

			apiMsg->h.u1.Length = 0x500028;
			apiMsg->h.u2.ZeroInit = 8;
			apiMsg->ApiNumber = DbgKmLoadDllApi;
			if (thread)
			{
				status = DbgkpQueueMessage(eprocess, thread, apiMsg, DEBUG_EVENT_NOWAIT, TargetDebugObject);
				if (!NT_SUCCESS(status) && apiMsg->u.LoadDll.FileHandle)
				{
					ObCloseHandle(apiMsg->u.LoadDll.FileHandle, 0i64);
				}
			}
			else
			{
				DbgkpSendApiMessage(eprocess, DEBUG_EVENT_NOWAIT | DEBUG_EVENT_READ, apiMsg);
				if (apiMsg->u.LoadDll.FileHandle)
					ObCloseHandle(apiMsg->u.LoadDll.FileHandle, 0i64);
				if (teb)
					teb->NtTib.ArbitraryUserPointer = NULL;
			}
		}
	}

	return;
}



NTSTATUS DbgkpPostFakeThreadMessages(
	PEPROCESS Process,
	PDEBUG_OBJECT DebugObject,
	PETHREAD	StartThread,
	PETHREAD* pFirstThread,
	PETHREAD* pLastThread)
{

	NTSTATUS status;
	PETHREAD Thread, FirstThread, LastThread, CurrentThread;
	DBGKM_APIMSG ApiMsg;
	BOOLEAN First = TRUE;
	BOOLEAN IsFirstThread;
	PIMAGE_NT_HEADERS NtHeaders;
	ULONG Flags;
	KAPC_STATE ApcState;

	status = STATUS_UNSUCCESSFUL;

	LastThread = FirstThread = NULL;

	CurrentThread = (PETHREAD)PsGetCurrentThread();

	if (StartThread == 0)
	{
		StartThread = (PETHREAD)PsGetNextProcessThread((PEPROCESS)Process, 0);
		First = TRUE;
	}
	else {
		First = FALSE;
		FirstThread = StartThread;
		ObReferenceObject(StartThread);
	}

	for (Thread = StartThread;
		Thread != NULL;
		Thread = (PETHREAD)PsGetNextProcessThread((PEPROCESS)Process, (PETHREAD)Thread))
	{

		Flags = DEBUG_EVENT_NOWAIT;

		if (LastThread != 0)
		{
			ObDereferenceObject(LastThread);
		}

		LastThread = Thread;
		ObReferenceObject(LastThread);
		if (IsThreadSystem(Thread))
		{
			continue;
		}


		if (!IsThreadInserted(Thread))//这里要注意下位操作
		{
			//这个涉及的内容也比较多，而且一般也不会进入这里，所以为了简单注释掉好了
			PsSynchronizeWithThreadInsertion(Thread, CurrentThread);
			if (!IsThreadInserted(Thread))
			{
				continue;
			}
		}

		if (EntryAcquireRundownProtectionByThread(Thread))
		{
			Flags |= DEBUG_EVENT_RELEASE;
			status = PsSuspendThread((PETHREAD)Thread, 0);
			if (NT_SUCCESS(status))
			{
				Flags |= DEBUG_EVENT_SUSPEND;
			}
		}
		else {
			Flags |= DEBUG_EVENT_PROTECT_FAILED;
		}

		//每次构造一个DBGKM_APIMSG结构
		memset(&ApiMsg, 0, sizeof(DBGKM_APIMSG));

		if (First && (Flags & DEBUG_EVENT_PROTECT_FAILED) == 0)
		{
			//进程的第一个线程才会到这里
			IsFirstThread = TRUE;
			ApiMsg.ApiNumber = DbgKmCreateProcessApi;
			PVOID pSection = GetSectionObject(Process);
			if (pSection)
			{
				ApiMsg.u.CreateProcessInfo.FileHandle = DbgkpProcessToFileHandle(Process);
			}
			else {
				ApiMsg.u.CreateProcessInfo.FileHandle = NULL;
			}
			ApiMsg.u.CreateProcessInfo.BaseOfImage = PsGetProcessSectionBaseAddress(Process);

			KeStackAttachProcess((PRKPROCESS)Process, &ApcState);

			__try {
				NtHeaders = RtlImageNtHeader(ApiMsg.u.CreateProcessInfo.BaseOfImage);
				if (NtHeaders)
				{
					ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress = NULL;
					ApiMsg.u.CreateProcessInfo.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
					ApiMsg.u.CreateProcessInfo.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
				}
			}_except(EXCEPTION_EXECUTE_HANDLER) {
				ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress = NULL;
				ApiMsg.u.CreateProcessInfo.DebugInfoFileOffset = 0;
				ApiMsg.u.CreateProcessInfo.DebugInfoSize = 0;
			}

			KeUnstackDetachProcess(&ApcState);
		}
		else {
			IsFirstThread = FALSE;
			ApiMsg.ApiNumber = DbgKmCreateThreadApi;
			ApiMsg.u.CreateThread.StartAddress = PsGetThreadStartAddress(Thread);//注意偏移
		}

		status = DbgkpQueueMessage(
			Process,
			Thread,
			&ApiMsg,
			Flags,
			DebugObject);

		if (!NT_SUCCESS(status))
		{
			if (Flags & DEBUG_EVENT_SUSPEND)
			{
				PsResumeThread((PETHREAD)Thread, NULL);
			}

			if (Flags & DEBUG_EVENT_RELEASE)
			{
				ExitReleaseRundownProtectionByThread(Thread);

			}

			if (ApiMsg.ApiNumber == DbgKmCreateProcessApi && ApiMsg.u.CreateProcessInfo.FileHandle != NULL)
			{
				ObCloseHandle(ApiMsg.u.CreateProcessInfo.FileHandle, KernelMode);
			}

			ObDereferenceObject(Thread);
			break;

		}
		else if (IsFirstThread) {
			First = FALSE;
			ObReferenceObject(Thread);
			FirstThread = Thread;

			DbgkSendSystemDllMessages(Thread, DebugObject, &ApiMsg);
		}
	}

	if (!NT_SUCCESS(status)) {
		if (FirstThread)
		{
			ObDereferenceObject(FirstThread);
		}
		if (LastThread != NULL)
		{
			ObDereferenceObject(LastThread);
		}
	}
	else {
		if (FirstThread) {
			*pFirstThread = FirstThread;
			*pLastThread = LastThread;
		}
		else {

			if (LastThread != NULL)
			{
				ObDereferenceObject(LastThread);
			}
			status = STATUS_UNSUCCESSFUL;
		}
	}
	return status;
}


NTSTATUS DbgkpPostModuleMessages(
	IN PEPROCESS Process,
	IN PETHREAD Thread,
	IN PDEBUG_OBJECT DebugObject)
{
	PMPEB peb = (PMPEB)PsGetProcessPeb(Process);
	DBGKM_APIMSG apiMsg;
	NTSTATUS status = STATUS_UNSUCCESSFUL;


	PLDR_DATA_TABLE_ENTRY list = (PLDR_DATA_TABLE_ENTRY)&peb->Ldr->InLoadOrderModuleList;
	if ((ULONG64)list >= MmUserProbeAddress)
	{
		return STATUS_UNSUCCESSFUL;
	}
	PLDR_DATA_TABLE_ENTRY listEntry = list;
	PLDR_DATA_TABLE_ENTRY listNext = (PLDR_DATA_TABLE_ENTRY)list->InLoadOrderLinks.Flink;
	ULONG count = 0;

	while (listEntry != listNext && count < g_DbgkpMaxModuleMsgs)
	{
		if (count > 1)
		{
			memset(&apiMsg, 0, sizeof(apiMsg));
			apiMsg.ApiNumber = DbgKmLoadDllApi;
			apiMsg.u.LoadDll.BaseOfDll = listNext->DllBase;
			PIMAGE_NT_HEADERS pNts = RtlImageNtHeader(apiMsg.u.LoadDll.BaseOfDll);
			if (pNts)
			{
				apiMsg.u.LoadDll.DebugInfoFileOffset = pNts->FileHeader.PointerToSymbolTable;
				apiMsg.u.LoadDll.DebugInfoSize = pNts->FileHeader.NumberOfSymbols;

			}

			UNICODE_STRING unName = { 0 };
			status = MmGetFileNameForAddress(apiMsg.u.LoadDll.BaseOfDll, &unName);
			if (NT_SUCCESS(status))
			{
				OBJECT_ATTRIBUTES ObjectAttributes;
				InitializeObjectAttributes(&ObjectAttributes, &unName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE | OBJ_FORCE_ACCESS_CHECK, NULL, NULL);
				IO_STATUS_BLOCK IoStatusBlock = { 0 };
				status = ZwOpenFile(&apiMsg.u.LoadDll.FileHandle, GENERIC_READ | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock, FILE_SHARE_VALID_FLAGS, FILE_SYNCHRONOUS_IO_NONALERT);
				if (!NT_SUCCESS(status)) {
					apiMsg.u.LoadDll.FileHandle = NULL;
				}

				ExFreePoolWithTag(unName.Buffer, 0);
			}

			if (DebugObject)
			{
				status = DbgkpQueueMessage(Process, Thread, &apiMsg, DEBUG_EVENT_NOWAIT, DebugObject);
			}
			else
			{
				DbgkpSendApiMessage(Process, DEBUG_EVENT_NOWAIT | DEBUG_READ_EVENT, &apiMsg);
				status = STATUS_UNSUCCESSFUL;
			}

			if (!NT_SUCCESS(status) && apiMsg.u.LoadDll.FileHandle)
			{
				ObCloseHandle(apiMsg.u.LoadDll.FileHandle, KernelMode);
				apiMsg.u.LoadDll.FileHandle = NULL;
			}
		}


		listNext = (PLDR_DATA_TABLE_ENTRY)listNext->InLoadOrderLinks.Flink;
		count++;
	}

	//在判断是不是wow64进程
	PPEB32 peb32 = PsGetProcessWow64Process(Process);
	if (!peb32) return STATUS_SUCCESS;

	PEB_LDR_DATA32* ldr32 = (PEB_LDR_DATA32*)ULongToPtr(peb32->Ldr);
	LDR_DATA_TABLE_ENTRY32* list32 = (LDR_DATA_TABLE_ENTRY32*)&ldr32->InLoadOrderModuleList;
	LDR_DATA_TABLE_ENTRY32* list32Next = (LDR_DATA_TABLE_ENTRY32*)list32->InLoadOrderLinks.Flink;

	count = 0;
	while (list32Next != list32 && count < g_DbgkpMaxModuleMsgs)
	{
		if (count > 1)
		{
			memset(&apiMsg, 0, sizeof(apiMsg));
			apiMsg.ApiNumber = DbgKmLoadDllApi;
			apiMsg.u.LoadDll.BaseOfDll = (PVOID)list32Next->DllBase;
			PIMAGE_NT_HEADERS pNts = RtlImageNtHeader(apiMsg.u.LoadDll.BaseOfDll);
			if (pNts)
			{
				apiMsg.u.LoadDll.DebugInfoFileOffset = pNts->FileHeader.PointerToSymbolTable;
				apiMsg.u.LoadDll.DebugInfoSize = pNts->FileHeader.NumberOfSymbols;

			}

			UNICODE_STRING unName = { 0 };
			status = MmGetFileNameForAddress(apiMsg.u.LoadDll.BaseOfDll, &unName);
			if (NT_SUCCESS(status))
			{
				PWCHAR findStr = wcsstr(unName.Buffer, L"\\SYSTEM32\\");
				if (findStr)
				{
					wcscpy(findStr + 1, L"SysWOW64");
				}
				OBJECT_ATTRIBUTES ObjectAttributes;
				InitializeObjectAttributes(&ObjectAttributes, &unName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE | OBJ_FORCE_ACCESS_CHECK, NULL, NULL);
				IO_STATUS_BLOCK IoStatusBlock = { 0 };
				status = ZwOpenFile(&apiMsg.u.LoadDll.FileHandle, GENERIC_READ | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock, FILE_SHARE_VALID_FLAGS, FILE_SYNCHRONOUS_IO_NONALERT);
				if (!NT_SUCCESS(status)) {
					apiMsg.u.LoadDll.FileHandle = NULL;
				}

				ExFreePoolWithTag(unName.Buffer, 0);
			}

			if (DebugObject)
			{
				status = DbgkpQueueMessage(Process, Thread, &apiMsg, DEBUG_EVENT_NOWAIT, DebugObject);
			}
			else
			{
				DbgkpSendApiMessage(Process,DEBUG_EVENT_NOWAIT | DEBUG_READ_EVENT, &apiMsg);
				status = STATUS_UNSUCCESSFUL;
			}

			if (!NT_SUCCESS(status) && apiMsg.u.LoadDll.FileHandle)
			{
				ObCloseHandle(apiMsg.u.LoadDll.FileHandle, KernelMode);
				apiMsg.u.LoadDll.FileHandle = NULL;
			}
		}

		count++;
		list32Next = (LDR_DATA_TABLE_ENTRY32*)list32Next->InLoadOrderLinks.Flink;
	}


	return count;
}




NTSTATUS DbgkpPostFakeProcessCreateMessages(
	IN PEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD* pLastThread)
{
	KAPC_STATE kApc = { 0 };
	PETHREAD pFisrtThread = NULL;
	PETHREAD pMLastThread = NULL;
	NTSTATUS status = DbgkpPostFakeThreadMessages(Process, DebugObject, NULL, &pFisrtThread, &pMLastThread);
	if (NT_SUCCESS(status))
	{
		KeStackAttachProcess(Process, &kApc);
		DbgkpPostModuleMessages(Process, pFisrtThread, DebugObject);
		KeUnstackDetachProcess(&kApc);
		ObfDereferenceObject(pFisrtThread);
		status = STATUS_SUCCESS;
	}

	*pLastThread = pMLastThread;
	return status;
}


NTSTATUS DbgkpSetProcessDebugObject(
	IN PEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN NTSTATUS MsgStatus,
	IN PETHREAD LastThread)
{
	NTSTATUS Status;
	PETHREAD ThisThread;
	LIST_ENTRY TempList;
	PLIST_ENTRY Entry;
	PDEBUG_EVENT DebugEvent;
	BOOLEAN First;
	PETHREAD Thread;
	BOOLEAN GlobalHeld;
	PETHREAD FirstThread;

	PAGED_CODE();

	ThisThread = (PETHREAD)PsGetCurrentThread();

	InitializeListHead(&TempList);

	First = TRUE;
	GlobalHeld = FALSE;

	if (!NT_SUCCESS(MsgStatus)) {
		LastThread = NULL;
		Status = MsgStatus;
	}
	else {
		Status = STATUS_SUCCESS;
	}


	if (NT_SUCCESS(Status)) {

		while (1) {

			GlobalHeld = TRUE;

			ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);

			

			if (HotGePsGetProcessDebugPort(Process)) {
				Status = STATUS_PORT_ALREADY_SET;
				break;
			}

			HotGePsSetProcessDebugPort(Process, DebugObject);

	
			ObfReferenceObject(LastThread);

		
			Thread = (PETHREAD)PsGetNextProcessThread((PEPROCESS)Process, (PETHREAD)LastThread);
			if (Thread != NULL) {

				HotGePsSetProcessDebugPort(Process, NULL);

				ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);

				GlobalHeld = FALSE;

				ObfDereferenceObject(LastThread);
		
				Status = DbgkpPostFakeThreadMessages(
					Process,
					DebugObject,
					Thread,
					&FirstThread,
					&LastThread);
				if (!NT_SUCCESS(Status)) {
					LastThread = NULL;
					break;
				}
				ObfDereferenceObject(FirstThread);
			}
			else {
				break;
			}
		}
	}

	ExAcquireFastMutex(&DebugObject->Mutex);

	if (NT_SUCCESS(Status)) {
		
		if ((DebugObject->Flags & DEBUG_EVENT_READ) == 0) {
			SetProcessFlags(Process, PS_PROCESS_FLAGS_NO_DEBUG_INHERIT | PS_PROCESS_FLAGS_CREATE_REPORTED);
			//RtlInterlockedSetBitsDiscardReturn(&Process->Flags, PS_PROCESS_FLAGS_NO_DEBUG_INHERIT | PS_PROCESS_FLAGS_CREATE_REPORTED);
			ObfReferenceObject(DebugObject);
		}
		else {
			HotGePsSetProcessDebugPort(Process, NULL);
			Status = STATUS_DEBUGGER_INACTIVE;
		}
	}

	
	
	for (Entry = DebugObject->EventList.Flink;
		Entry != &DebugObject->EventList;
		) {
		//取出调试事件
		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		Entry = Entry->Flink;


		if ((DebugEvent->Flags & 0x4) != 0 && DebugEvent->BackoutThread == (PETHREAD)ThisThread) {
			Thread = DebugEvent->Thread;

			if (NT_SUCCESS(Status)) {
				
				if ((DebugEvent->Flags & DEBUG_EVENT_PROTECT_FAILED) != 0) {
					SetThreadCrossThreadFlags(Thread, PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG);
					//RtlInterlockedSetBitsDiscardReturn(&Thread->CrossThreadFlags,
					//	0x100);
					RemoveEntryList(&DebugEvent->EventList);
					InsertTailList(&TempList, &DebugEvent->EventList);
				}
				else {
					
					if (First) {
						DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
						KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
						First = FALSE;
					}
					
					DebugEvent->BackoutThread = NULL;
					SetThreadCrossThreadFlags(Thread, PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG);
					//RtlInterlockedSetBitsDiscardReturn(&Thread->CrossThreadFlags,0x80);

				}
			}
			else {
				
				RemoveEntryList(&DebugEvent->EventList);
				InsertTailList(&TempList, &DebugEvent->EventList);
			}
			
			if (DebugEvent->Flags & DEBUG_EVENT_RELEASE) {
				DebugEvent->Flags &= ~DEBUG_EVENT_RELEASE;
				ExitReleaseRundownProtectionByThread(Thread);
			}

		}
	}

	ExReleaseFastMutex(&DebugObject->Mutex);

	if (GlobalHeld) {
		ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);
	}

	if (LastThread != NULL) {
		ObDereferenceObject(LastThread);
	}

	
	while (!IsListEmpty(&TempList)) {
		Entry = RemoveHeadList(&TempList);
		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		DbgkpWakeTarget(DebugEvent);
	}

	if (NT_SUCCESS(Status)) {

		ResetBreakPoint(PsGetCurrentProcess());
		//DbgkpMarkProcessPeb(Process);
	}

	return Status;
}

PVOID GeExceptionPort(PEPROCESS Process)
{

	ULONG64 value = *(PULONG64)((ULONG64)Process + g_NtSymbolOffset.EPROCESS_ExceptionPortData);
	return (PVOID)value;
}
PULONG_PTR GetProcessExPush(PEPROCESS Process)
{
	return (PULONG_PTR)((PUCHAR)Process + g_NtSymbolOffset.EPROCESS_ProcessLock);
}


PVOID PsCaptureExceptionPort(IN PEPROCESS Process)
{
	//PKTHREAD	Thread;
	PVOID		ExceptionPort;

	ExceptionPort = GeExceptionPort(Process);
	if (ExceptionPort != NULL)
	{
		KeEnterCriticalRegion();
		ExfAcquirePushLockShared(GetProcessExPush(Process));
		ExceptionPort = (PVOID)((ULONG_PTR)ExceptionPort & ~0x7);
		ObfReferenceObject(ExceptionPort);
		ExfReleasePushLockShared(GetProcessExPush(Process));
		KeLeaveCriticalRegion();

	}

	return ExceptionPort;
}


BOOLEAN  DbgkForwardException(IN PEXCEPTION_RECORD ExceptionRecord, IN BOOLEAN DebugException, IN BOOLEAN SecondChance)
{
	DBGKM_APIMSG apiMsg = { 0 };
	PEPROCESS Process = PsGetCurrentProcess();
	// CurrentThread = PsGetCurrentThread();
	PDEBUG_OBJECT pDebugObject = NULL;
	BOOLEAN bLpcPort = FALSE;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID ExceptionPort = NULL;

	apiMsg.h.u1.Length = 0xD000A8;
	apiMsg.h.u2.ZeroInit = 8;
	apiMsg.ApiNumber = DbgKmExceptionApi;

	DbgPrintEx(77, 0, "---------ExceptionAddress------------------%p\r\n", ExceptionRecord->ExceptionAddress);
	if (DebugException)
	{
		/*
		if (IsThreadHideFromDebugger(Thread))
		{
			return FALSE;
		}
		*/
		pDebugObject = (PDEBUG_OBJECT)HotGePsGetProcessDebugPort(Process);
	}
	else
	{
		ExceptionPort = (PDEBUG_OBJECT)PsCaptureExceptionPort(Process);
		apiMsg.h.u2.ZeroInit = 0x7;
		bLpcPort = TRUE;
	}


	if (pDebugObject == NULL && DebugException == TRUE && ExceptionPort == NULL)
	{
		return FALSE;
	}

	apiMsg.u.Exception.ExceptionRecord = *ExceptionRecord;
	apiMsg.u.Exception.FirstChance = !SecondChance;

	if (!bLpcPort)
	{
		status = DbgkpSendApiMessage(Process,DebugException, &apiMsg);
	}
	else if (ExceptionPort)
	{
		status = DbgkpSendApiMessageLpc(&apiMsg, ExceptionPort, DebugException);
		ObDereferenceObject(ExceptionPort);
	}
	else
	{
		apiMsg.ReturnedStatus = DBG_EXCEPTION_NOT_HANDLED;
		status = STATUS_SUCCESS;
	}

	if (NT_SUCCESS(status))
	{
		status = apiMsg.ReturnedStatus;

		if (apiMsg.ReturnedStatus == DBG_EXCEPTION_NOT_HANDLED)
		{
			if (DebugException == TRUE)
			{
				return FALSE;
			}

			status = DbgkpSendErrorMessage(ExceptionRecord, 0, &apiMsg);
		}
	}

	return NT_SUCCESS(status);
}