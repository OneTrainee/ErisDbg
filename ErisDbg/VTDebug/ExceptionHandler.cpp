#include <ntifs.h>
#include <ntddk.h>
#include "..\UtilsVT.h"
#include "..\ia32_type.h"
#include "..\NtFunction.h"
#include "BreakPoint.h"
#include "DebugEvent.h"
#include "DebugObject.h"

ULONG64 debuggedProcessCr3;



BOOLEAN Int3Handler() {

	ULONG64 rip = UtilVmRead(VmcsField::kGuestRip);
	ULONG64 cr3 = UtilVmRead(VmcsField::kGuestCr3);

	if (debuggedProcessCr3 != cr3) {
		return FALSE;
	}

	PBreakPointEntry pBreakPointEntry = FindBreakpointEntryByAddress(rip);
	if (!pBreakPointEntry) {
		return FALSE;
	}

	PNYX_DEBUG_EVENT pNyxDebugEvent = GenerateDebugEventBreakPoint(rip - 1);

	InsertDebugEventIntoDebugObject(pNyxDebugEvent);

	return TRUE;
}