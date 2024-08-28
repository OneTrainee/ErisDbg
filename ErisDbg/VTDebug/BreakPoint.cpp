#include <ntifs.h>
#include <ntddk.h>
#include "BreakPoint.h"


LIST_ENTRY BreakPointList;

void InitializeBreakPointList() {
	InitializeListHead(&BreakPointList);
}

void InsertBreakPoint(ULONG64 address, UCHAR oldChar) {
	PBreakPointEntry newEntry = (PBreakPointEntry)ExAllocatePool(NonPagedPool, sizeof(BreakPointEntry));
	if (newEntry == NULL) {
		return;
	}
	newEntry->bpAddress = address;
	newEntry->oldChr = oldChar;
	InsertTailList(&BreakPointList, &newEntry->entry);
}

PBreakPointEntry FindBreakpointEntryByAddress(ULONG64 address) {

	PLIST_ENTRY entry;
	PBreakPointEntry bpEntry;
	PLIST_ENTRY pBreakPointList = &BreakPointList;

	for (entry = pBreakPointList->Flink; entry != pBreakPointList; entry = entry->Flink) {
		bpEntry = CONTAINING_RECORD(entry, BreakPointEntry, entry);
		if (bpEntry->bpAddress == address) {
			return bpEntry;
		}
	}

	return NULL;
}

VOID RemoveBreakPointEntry(PBreakPointEntry pBreakPointEntry) {
	RemoveEntryList(&pBreakPointEntry->entry);
	ExFreePool(pBreakPointEntry);
}