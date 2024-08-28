#pragma once
#include <ntifs.h>
#include <ntddk.h>

EXTERN_C VOID
KeSignalCallDpcDone(
	_In_ PVOID SystemArgument1
);

EXTERN_C LOGICAL
KeSignalCallDpcSynchronize(
	_In_ PVOID SystemArgument2
);

EXTERN_C VOID
KeGenericCallDpc(
	_In_ PKDEFERRED_ROUTINE Routine,
	_In_opt_ PVOID Context
);