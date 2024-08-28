#pragma once
#include "DebugEvent.h"

typedef struct _NYX_DEBUG_OBJECT {
	KEVENT EventsPresent;
	FAST_MUTEX Mutex;
	LIST_ENTRY EventList;
	ULONG Flags;
	ULONG un1;
} NYX_DEBUG_OBJECT, * PNYX_DEBUG_OBJECT;

BOOLEAN InsertDebugEventIntoDebugObject(PNYX_DEBUG_EVENT pNyxDebugEvent);