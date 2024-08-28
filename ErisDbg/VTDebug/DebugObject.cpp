#include <ntifs.h>
#include "DebugEvent.h"
#include "..\NtFunction.h"
#include "DebugObject.h"
#include "..\RebuiltDbgSystem\dbg.h"

NYX_DEBUG_OBJECT  g_NyxDebugObject;

BOOLEAN InsertDebugEventIntoDebugObject(PNYX_DEBUG_EVENT pNyxDebugEvent) {

	KeEnterCriticalRegion();


	*((USHORT*)((PUCHAR)pNyxDebugEvent->Thread + g_NtSymbolOffset.ETHREAD_KernelApcDisable)) -= 1;

	
	if (!PsFreezeProcess(pNyxDebugEvent->Process, FALSE)) {
		KeLeaveCriticalRegion();
		ExFreePool(pNyxDebugEvent);
		return FALSE;
	}

	ExAcquireFastMutex(&g_NyxDebugObject.Mutex);

	
	InsertTailList(&g_NyxDebugObject.EventList, &pNyxDebugEvent->EventList);

	
	KeSetEvent(&g_NyxDebugObject.EventsPresent, 0, 0);

	ExReleaseFastMutex(&g_NyxDebugObject.Mutex);


	KeWaitForSingleObject(&pNyxDebugEvent->ContinueEvent, Executive, KernelMode, FALSE, NULL);


	
	PsThawProcess(pNyxDebugEvent->Process, FALSE);
	KeLeaveCriticalRegion();


	ExFreePool(pNyxDebugEvent);

	return TRUE;
}


VOID NyxDbgkpConvertKernelToUserStateChange(PNYX_DBGUI_WAIT_STATE_CHANGE WaitStateChange, PNYX_DEBUG_EVENT DebugEvent)
{
	WaitStateChange->AppClientId = DebugEvent->ClientId;
	switch (DebugEvent->ApiMsg.ApiNumber) {
	case NYX_DBGKM_APINUMBER::DbgKmExceptionApi:
		switch (DebugEvent->ApiMsg.u.Exception.ExceptionRecord.ExceptionCode) {
		case STATUS_BREAKPOINT:
			WaitStateChange->NewState = _NYX_DBG_STATE::DbgBreakpointStateChange;
			break;
#if 0 
		case STATUS_SINGLE_STEP:
			WaitStateChange->NewState = _NYX_DBG_STATE::DbgSingleStepStateChange;
			break;
#endif
		default:
			WaitStateChange->NewState = _NYX_DBG_STATE::DbgExceptionStateChange;
			break;
		}
		WaitStateChange->StateInfo.Exception = DebugEvent->ApiMsg.u.Exception;
		break;

#if 0
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
#endif 
	default:
		ASSERT(FALSE);
	}
}

NTSTATUS NyxWaitForDebugEvent(BOOLEAN Alertable, PLARGE_INTEGER Timeout, PNYX_DBGUI_WAIT_STATE_CHANGE WaitStateChange) {
	
	NYX_DBGUI_WAIT_STATE_CHANGE newStateChange;
	NTSTATUS status;
	BOOLEAN GotEvent;
	PNYX_DEBUG_EVENT DebugEvent;
	PLIST_ENTRY Entry;

	GotEvent = FALSE;
	do{

		status = KeWaitForSingleObject(&g_NyxDebugObject.EventsPresent, Executive, KernelMode, Alertable, Timeout);

		if (!NT_SUCCESS(status) || status == STATUS_TIMEOUT || status == STATUS_ALERTED || status == STATUS_USER_APC) {
			break;
		}

		DebugEvent = NULL;

		ExAcquireFastMutex(&g_NyxDebugObject.Mutex);


		// 
		for (Entry = g_NyxDebugObject.EventList.Flink; Entry != &g_NyxDebugObject.EventList; Entry = Entry->Flink) {

			DebugEvent = CONTAINING_RECORD(Entry, NYX_DEBUG_EVENT, EventList);

			// 
			if ((DebugEvent->Flags & (DEBUG_EVENT_READ | DEBUG_EVENT_INACTIVE)) == 0) {
				GotEvent = true;
			}

			if (GotEvent) {
				break;
			}
		}

		if (GotEvent) {
			NyxDbgkpConvertKernelToUserStateChange(&newStateChange, DebugEvent); // 
			DebugEvent->Flags |= DEBUG_EVENT_READ; // 
		}
		else {
			KeClearEvent(&g_NyxDebugObject.EventsPresent);
		}

		ExReleaseFastMutex(&g_NyxDebugObject.Mutex);


#if 0 
		if (MTimeout.QuadPart < 0) {
			LARGE_INTEGER NewTime;
			KeQuerySystemTime(&NewTime);
			MTimeout.QuadPart = MTimeout.QuadPart + (NewTime.QuadPart - StartTime.QuadPart);
			StartTime = NewTime;
			if (MTimeout.QuadPart >= 0) {
				status = STATUS_TIMEOUT;
				break;
			}
		}
#endif
	} while (0);

	// 
	*WaitStateChange = newStateChange;

	return status;
}


VOID NyxDbgkpWakeTarget(IN PNYX_DEBUG_EVENT DebugEvent)
{

	if ((DebugEvent->Flags & DEBUG_EVENT_NOWAIT) == 0) {
		KeSetEvent(&DebugEvent->ContinueEvent, 0, FALSE); // Wake up waiting process
	}
	else {
		ExFreePool(DebugEvent);
	}

}


NTSTATUS NyxDebugContinue(PCLIENT_ID ClientId, NTSTATUS ContinueStatus) {
	BOOLEAN GotEvent;
	PLIST_ENTRY Entry;
	PNYX_DEBUG_EVENT DebugEvent, FoundDebugEvent;
	ExAcquireFastMutex(&g_NyxDebugObject.Mutex);
	CLIENT_ID Clid;


	Clid = *ClientId;
	GotEvent = FALSE;
	FoundDebugEvent = NULL;

	
	for (Entry = g_NyxDebugObject.EventList.Flink; 
		Entry != &g_NyxDebugObject.EventList; 
		Entry = Entry->Flink) {

		DebugEvent = CONTAINING_RECORD(Entry, NYX_DEBUG_EVENT, EventList);
		if (!GotEvent) {
			if (DebugEvent->ClientId.UniqueProcess == Clid.UniqueProcess) {
				if (DebugEvent->ClientId.UniqueThread == Clid.UniqueThread &&
					(DebugEvent->Flags & DEBUG_EVENT_READ) != 0) { 
					RemoveEntryList(Entry);
					FoundDebugEvent = DebugEvent;
					GotEvent = TRUE;
				}
			}
		}
		else {
			DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE; 
			KeSetEvent(&g_NyxDebugObject.EventsPresent, 0, FALSE);
			break;
		}
	}

	if (GotEvent) {
		FoundDebugEvent->ApiMsg.ReturnedStatus = ContinueStatus;
		FoundDebugEvent->Status = STATUS_SUCCESS;
		NyxDbgkpWakeTarget(FoundDebugEvent);
	}

	return STATUS_SUCCESS;

}