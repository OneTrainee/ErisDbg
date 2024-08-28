#pragma once

#include "dbgStruct.h"
VOID DbgkpConvertKernelToUserStateChange(PDBGUI_WAIT_STATE_CHANGE WaitStateChange, PDEBUG_EVENT DebugEvent);
VOID DbgkpOpenHandles(PDBGUI_WAIT_STATE_CHANGE WaitStateChange, PEPROCESS Process, PETHREAD Thread);
BOOLEAN EntryAcquireRundownProtectionByProcess(PEPROCESS eprocess);

NTSTATUS DbgkpPostFakeProcessCreateMessages( IN PEPROCESS Process,IN PDEBUG_OBJECT DebugObject,IN PETHREAD* pLastThread);
NTSTATUS DbgkpSetProcessDebugObject(
	IN PEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN NTSTATUS MsgStatus,
	IN PETHREAD LastThread);

VOID ExitReleaseRundownProtectionByProcess(PEPROCESS eprocess);
VOID DbgkpWakeTarget(IN PDEBUG_EVENT DebugEvent);
BOOLEAN  DbgkForwardException(IN PEXCEPTION_RECORD ExceptionRecord, IN BOOLEAN DebugException, IN BOOLEAN SecondChance);