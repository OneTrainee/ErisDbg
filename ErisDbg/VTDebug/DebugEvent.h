#pragma once
#include <ntifs.h>

typedef enum class _NYX_DBGKM_APINUMBER {
	DbgKmExceptionApi,
	DbgKmCreateThreadApi,
	DbgKmCreateProcessApi,
	DbgKmExitThreadApi,
	DbgKmExitProcessApi,
	DbgKmLoadDllApi,
	DbgKmUnloadDllApi,
	DbgKmMaxApiNumber
} NYX_DBGKM_APINUMBER;

typedef struct _NYX_DBGKM_EXCEPTION {
	EXCEPTION_RECORD ExceptionRecord;
	ULONG FirstChance;
} NYX_DBGKM_EXCEPTION, * PNYX_DBGKM_EXCEPTION;

typedef struct _NYX_DBGKM_APIMSG {
	// PORT_MESSAGE h;  // 
	NYX_DBGKM_APINUMBER ApiNumber;
	NTSTATUS ReturnedStatus;
	union {
		NYX_DBGKM_EXCEPTION Exception;
		//DBGKM_CREATE_THREAD CreateThread;
		//DBGKM_CREATE_PROCESS CreateProcessInfo;
		//DBGKM_EXIT_THREAD ExitThread;
		//DBGKM_EXIT_PROCESS ExitProcess;
		//DBGKM_LOAD_DLL LoadDll;
		//DBGKM_UNLOAD_DLL UnloadDll;
	} u;
	UCHAR unknow[0x40];
} NYX_DBGKM_APIMSG, * PNYX_DBGKM_APIMSG;

typedef struct _NYX_DEBUG_EVENT {
	LIST_ENTRY EventList;
	KEVENT ContinueEvent;
	CLIENT_ID ClientId;
	PEPROCESS Process;
	PETHREAD Thread;
	NTSTATUS Status;
	ULONG Flags;
	// PETHREAD BackoutThread;
	NYX_DBGKM_APIMSG ApiMsg;
}NYX_DEBUG_EVENT, *PNYX_DEBUG_EVENT;

typedef enum class _NYX_DBG_STATE {
	DbgIdle,
	DbgReplyPending,
	DbgCreateThreadStateChange,
	DbgCreateProcessStateChange,
	DbgExitThreadStateChange,
	DbgExitProcessStateChange,
	DbgExceptionStateChange,
	DbgBreakpointStateChange,
	DbgSingleStepStateChange,
	DbgLoadDllStateChange,
	DbgUnloadDllStateChange
} NYX_DBG_STATE, * PBTX_DBG_STATE;

typedef struct _NYX_DBGUI_WAIT_STATE_CHANGE {
	NYX_DBG_STATE NewState;
	CLIENT_ID AppClientId;
	union {
		NYX_DBGKM_EXCEPTION Exception;
		//DBGUI_CREATE_THREAD CreateThread;
		//DBGUI_CREATE_PROCESS CreateProcessInfo;
		//DBGKM_EXIT_THREAD ExitThread;
		//DBGKM_EXIT_PROCESS ExitProcess;
		//DBGKM_LOAD_DLL LoadDll;
		//DBGKM_UNLOAD_DLL UnloadDll;
	} StateInfo;
} NYX_DBGUI_WAIT_STATE_CHANGE, * PNYX_DBGUI_WAIT_STATE_CHANGE;

PNYX_DEBUG_EVENT GenerateDebugEventBreakPoint(ULONG64 address);