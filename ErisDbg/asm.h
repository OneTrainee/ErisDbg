#pragma once
#include <ntifs.h>
#include "ia32_type.h"

EXTERN_C{
	void __fastcall AsmVmmEntryPoint();
	BOOLEAN AsmVmxLaunch(PVOID callBack);

	USHORT __stdcall AsmReadCS();
	USHORT __stdcall AsmReadES();
	USHORT __stdcall AsmReadSS();
	USHORT __stdcall AsmReadDS();
	USHORT __stdcall AsmReadFS();
	USHORT __stdcall AsmReadGS();
	USHORT __stdcall AsmReadLDTR();
	USHORT __stdcall AsmReadTR();

	void __fastcall AsmWriteGDT(const Gdtr* gdtr);
	void _sgdt(void*);
	void __fastcall AsmInvd();
	unsigned char __stdcall AsmInvvpid(InvVpidType invvpid_type, const InvVpidDescriptor* invvpid_descriptor);
	ULONG_PTR __fastcall AsmLoadAccessRightsByte(ULONG_PTR segment_selector);

	void __fastcall AsmVmxCall(ULONG_PTR num, ULONG_PTR param);
	VOID AsmVmCall(ULONG exitCode, ULONG64 kernelCr3, ULONG64 CodePfNumber, ULONG64 DataPfNumber, PULONG64 retValue);
	void Asminvept(ULONG type, ULONG64 eptp);
}