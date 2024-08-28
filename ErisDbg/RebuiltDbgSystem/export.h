#pragma once
#include <ntifs.h>
#include "ObjectType.h"
EXTERN_C NTSTATUS ObCreateObject(
	__in KPROCESSOR_MODE ProbeMode,
	__in POBJECT_TYPE ObjectType,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in KPROCESSOR_MODE OwnershipMode,
	__inout_opt PVOID ParseContext,
	__in ULONG ObjectBodySize,
	__in ULONG PagedPoolCharge,
	__in ULONG NonPagedPoolCharge,
	__out PVOID* Object
);

EXTERN_C NTSTATUS ObCreateObjectType(
	__in PUNICODE_STRING TypeName,
	__in POBJECT_TYPE_INITIALIZER ObjectTypeInitializer,
	__in_opt PSECURITY_DESCRIPTOR SecurityDescriptor,
	__out POBJECT_TYPE* ObjectType
);

EXTERN_C NTSTATUS PsReferenceProcessFilePointer(
	IN PEPROCESS Process,
	OUT PVOID* OutFileObject
);


EXTERN_C PVOID PsGetProcessSectionBaseAddress(PEPROCESS eprocess);

EXTERN_C PIMAGE_NT_HEADERS RtlImageNtHeader(PVOID baseAddr);


EXTERN_C VOID DECLSPEC_NOINLINE FASTCALL ExfAcquirePushLockShared(__inout PEX_PUSH_LOCK PushLock);

EXTERN_C VOID DECLSPEC_NOINLINE FASTCALL ExfReleasePushLockShared(__inout PEX_PUSH_LOCK PushLock);