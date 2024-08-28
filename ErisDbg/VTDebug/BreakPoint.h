#pragma once
#include <ntifs.h>
typedef struct _BreakPointEntry {
	LIST_ENTRY entry;
	ULONG64 bpAddress;
	UCHAR oldChr;
}BreakPointEntry, * PBreakPointEntry;


PBreakPointEntry FindBreakpointEntryByAddress(ULONG64 address);

VOID RemoveBreakPointEntry(PBreakPointEntry pBreakPointEntry);

void InsertBreakPoint(ULONG64 address, UCHAR oldChar);

void InitializeBreakPointList();