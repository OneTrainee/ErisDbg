#include <ntifs.h>
#include "DebugEvent.h"


PNYX_DEBUG_EVENT GenerateDebugEventBreakPoint(ULONG64 address) {

	PNYX_DEBUG_EVENT pNyxDebugEvent = (PNYX_DEBUG_EVENT)ExAllocatePool(NonPagedPool, sizeof(NYX_DEBUG_EVENT));
	if (!pNyxDebugEvent) {
		return NULL;
	}

	RtlZeroMemory(pNyxDebugEvent, sizeof(PNYX_DEBUG_EVENT));
	
	KeInitializeEvent(&pNyxDebugEvent->ContinueEvent, SynchronizationEvent, FALSE);

	pNyxDebugEvent->ClientId.UniqueProcess = PsGetCurrentProcessId();
	pNyxDebugEvent->ClientId.UniqueThread = PsGetCurrentThreadId();

	pNyxDebugEvent->Process = PsGetCurrentProcess();
	pNyxDebugEvent->Thread = PsGetCurrentThread();

	pNyxDebugEvent->Flags = 0;

	pNyxDebugEvent->ApiMsg.ApiNumber = NYX_DBGKM_APINUMBER::DbgKmExceptionApi;
	pNyxDebugEvent->ApiMsg.u.Exception.FirstChance = TRUE;
	pNyxDebugEvent->ApiMsg.u.Exception.ExceptionRecord.ExceptionAddress = (PVOID)address;
	pNyxDebugEvent->ApiMsg.u.Exception.ExceptionRecord.ExceptionCode = STATUS_BREAKPOINT;
	pNyxDebugEvent->ApiMsg.u.Exception.ExceptionRecord.ExceptionFlags = 0; // ����Ϊ�㣬û������
	pNyxDebugEvent->ApiMsg.u.Exception.ExceptionRecord.ExceptionRecord = NULL;	// ����Ƕ�׵��쳣

	return pNyxDebugEvent;
}