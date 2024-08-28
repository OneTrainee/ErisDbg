#pragma once
#include <ntifs.h>

typedef struct _OBJECT_TYPE_INITIALIZER
{
	UINT16       Length;
	union
	{
		UINT8        ObjectTypeFlags;
		struct
		{
			UINT8        CaseInsensitive : 1;
			UINT8        UnnamedObjectsOnly : 1;
			UINT8        UseDefaultObject : 1;
			UINT8        SecurityRequired : 1;
			UINT8        MaintainHandleCount : 1;
			UINT8        MaintainTypeList : 1;
			UINT8        SupportsObjectCallbacks : 1;
		};
	};
	ULONG32      ObjectTypeCode;
	ULONG32      InvalidAttributes;
	struct _GENERIC_MAPPING GenericMapping;
	ULONG32      ValidAccessMask;
	ULONG32      RetainAccess;
	enum _POOL_TYPE PoolType;
	ULONG32      DefaultPagedPoolCharge;
	ULONG32      DefaultNonPagedPoolCharge;
	PVOID        DumpProcedure;
	PVOID        OpenProcedure;
	PVOID         CloseProcedure;
	PVOID         DeleteProcedure;
	PVOID         ParseProcedure;
	PVOID        SecurityProcedure;
	PVOID         QueryNameProcedure;
	PVOID         OkayToCloseProcedure;
}OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER;

typedef struct _MOBJECT_TYPE
{
	struct _LIST_ENTRY TypeList;                                            //0x0
	struct _UNICODE_STRING Name;                                            //0x10
	VOID* DefaultObject;                                                    //0x20
	UCHAR Index;                                                            //0x28
	ULONG TotalNumberOfObjects;                                             //0x2c
	ULONG TotalNumberOfHandles;                                             //0x30
	ULONG HighWaterNumberOfObjects;                                         //0x34
	ULONG HighWaterNumberOfHandles;                                         //0x38
	struct _OBJECT_TYPE_INITIALIZER TypeInfo;                               //0x40
	EX_PUSH_LOCK TypeLock;                                          //0xb0
	ULONG Key;                                                              //0xb8
	struct _LIST_ENTRY CallbackList;                                        //0xc0
}MOBJECT_TYPE, * PMOBJECT_TYPE;

PVOID GetTypeIndexTable();
PMOBJECT_TYPE GetObjectTypeByName(PWCH typeName);

POBJECT_TYPE GetHotGetType();