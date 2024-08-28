#include <ntifs.h>
#include <ntddk.h>
#include "dbg.h"
#include "SearchCode.h"
#include "..\pagehook.h"
#include "..\NtFunction.h"
#include "Dbgkp.h"

BOOLEAN HookNtCreateDebugObject() {

	//ULONG64 NtCreateDebugObjectAddr = SearchNtCodeHead("415648******418BF1448BF2488BF965********8A88****84C974*48*********483BFA480F42D7488B02", -0xfL);
	ULONG64 NtCreateDebugObjectAddr = NtCreateDebugObjectFuncAddr();
	PVOID tmp;
	// 	EptPageHook3(NtOpenProcess, reinterpret_cast<PVOID*>(&auxiliary_Function), MyOpenProcess);
	return EptPageHook3(reinterpret_cast<PVOID>(NtCreateDebugObjectAddr), &tmp, SelfNtCreateDebugObject);
}

BOOLEAN HookNtWaitForDebugEvent() {

	//ULONG64 NtWaitForDebugEventAddr = SearchNtCodeHead("4889******498BF1408AFA8854**488BD94C89***4533F64C89***4C89***65********448A*****33D241*****", -0x1dL);
	ULONG64 NtWaitForDebugEventAddr = NtWaitForDebugEventFuncAddr();
	PVOID tmp; 
	// 	EptPageHook3(NtOpenProcess, reinterpret_cast<PVOID*>(&auxiliary_Function), MyOpenProcess);
	return EptPageHook3(reinterpret_cast<PVOID>(NtWaitForDebugEventAddr), &tmp, SelfNtWaitForDebugEvent);
}

BOOLEAN HookNtDebugActiveProcess() {

	//ULONG64 NtDebugActiveProcessAddr = SearchNtCodeHead("4833C44889******65********4C8BF24883****BA****4883****4C******408A*****488D***4889***448ACDC744******E8****", -0x1cL);
	ULONG64 NtDebugActiveProcessAddr = NtDebugActiveProcessFuncAddr();
	PVOID tmp; 	
	// 	EptPageHook3(NtOpenProcess, reinterpret_cast<PVOID*>(&auxiliary_Function), MyOpenProcess);
	return EptPageHook3(reinterpret_cast<PVOID>(NtDebugActiveProcessAddr), &tmp, SelfNtDebugActiveProcess);
}


BOOLEAN HookNtDebugContinue() {

	// ULONG64 NtDebugContinueAddr = SearchNtCodeHead("48***418BD833C04989**4989**65********448A*****4584C974*48*********483BD0480F42C28A00", -0x15L);
	ULONG64 NtDebugContinueAddr = NtDebugContinueFuncAddr();
	PVOID tmp; 	
	// 	EptPageHook3(NtOpenProcess, reinterpret_cast<PVOID*>(&auxiliary_Function), MyOpenProcess);
	return EptPageHook3(reinterpret_cast<PVOID>(NtDebugContinueAddr), &tmp, SelfNtDebugContinue);
}
		 
BOOLEAN HookDbgkForwardException() {

	// ULONG64 DbgkForwardExceptionAddr = SearchNtCodeHead("4889**458AF8408AFA4C8BE133D241*****488D***E8****4584FF0F*****8364***C744******C744******65********", -0x28L);
	ULONG64 DbgkForwardExceptionAddr = NtDbgkForwardExceptionFuncAddr();
	PVOID tmp; 
	// 	EptPageHook3(NtOpenProcess, reinterpret_cast<PVOID*>(&auxiliary_Function), MyOpenProcess);
	return EptPageHook3(reinterpret_cast<PVOID>(DbgkForwardExceptionAddr), &tmp, DbgkForwardException);
}



VOID InitDBG() {

	// Hook  NtCreateDebugObject

	// 
	HotGetDbgkInitialize();

	HookNtCreateDebugObject();

	HookNtWaitForDebugEvent();

	HookNtDebugActiveProcess();

	HookNtDebugContinue();

	HookDbgkForwardException();
}