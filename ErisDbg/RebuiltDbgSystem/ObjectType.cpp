#include "ObjectType.h"

PVOID GetTypeIndexTable()
{
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&version));
	LARGE_INTEGER in = { 0 };
	PUCHAR typeAddr = 0;

	UNICODE_STRING funcName = { 0 };
	RtlInitUnicodeString(&funcName, L"ObGetObjectType");
	PUCHAR MyObGetObjectType = (PUCHAR)MmGetSystemRoutineAddress(&funcName);

	if (!MyObGetObjectType) return NULL;

	if (version.dwMajorVersion <= 6)
	{
		typeAddr = ((PUCHAR)MyObGetObjectType + 7);


	}
	else
	{
		typeAddr = ((PUCHAR)MyObGetObjectType + 0x1F);
	}

	if (!typeAddr) return NULL;

	in.QuadPart = (ULONG64)(typeAddr + 4);
	in.LowPart += *((PULONG)typeAddr);
	return (PVOID)in.QuadPart;
}

PMOBJECT_TYPE GetObjectTypeByName(PWCH typeName)
{

	PULONG64 table = (PULONG64)GetTypeIndexTable();
	if (!table) return NULL;

	UNICODE_STRING tName = { 0 };
	RtlInitUnicodeString(&tName, typeName);
	PMOBJECT_TYPE retObjType = NULL;

	for (int i = 0; i < 0xFF; i++)
	{
		PMOBJECT_TYPE type = (PMOBJECT_TYPE)table[i];
		if (type && MmIsAddressValid(type))
		{

			if (RtlCompareUnicodeString(&type->Name, &tName, TRUE) == 0)
			{
				retObjType = type;
				break;
			}
		}

	}

	return retObjType;
}

POBJECT_TYPE GetHotGetType()
{
	//return GetObjectTypeByName(L"HotGeObject");
	auto pmobject = GetObjectTypeByName(L"DebugObject");
	return reinterpret_cast<POBJECT_TYPE>(pmobject);
}