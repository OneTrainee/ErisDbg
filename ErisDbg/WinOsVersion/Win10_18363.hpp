FunctionSignatureItem functionTable_Win10_18363[] = {
	{0,	"ObDuplicateObject",					-0x1c,	"48******4833C44889*****8BBD****498BF04889***4C8BF933D24889**488D**4D8BE1448D**E8****33D2"},
	{0,	"PsSynchronizeWithThreadInsertion",		-0x2,	"48***66FF*****488BDA48******F0****488B01A8*74*E8****488BCBE8****48***"},
	{0,	"PsSuspendThread",						-0x1b,	"8364***65********4889***66FF*****4C8D*****4C89***498BCFE8****84C00F*****8B87****A8*0F*****488BCFE8****8944**33DB895C**EB*"},
	{0,	"PsGetNextProcessThread",				-0x34,	"448BF36641*******488D*****33D2488BCDE8****4885FF0F*****488B*****"},
	{0,	"PsResumeThread",						-0xa,	"5748***488BDA488BF9E8****65********8BF083**75*4C8B*****B8****418B*****85C874*"},
	{0, "PsQuerySystemDllInfo",					-0x3,	"48******488B04C14885C074*4883***74*48***C3" },
	{0, "PsFreezeProcess",						-0x14,	"8B81****8ADA488BF9A8*0F*****E8****8B8F****F6**0F*****65********85C075*8B87****0F***"},
	{0, "KeLeaveCriticalRegionThread",			0x0,	"48***6683******75*488D*****48390075*48***C3"},
	{0,	"PsThawProcess"	,						-0xb,	"5741544156415748***408AF2488BF965********4C89***84D20F*****4883******74*8B81****A8*75*"},
	{0, "MmGetFileNameForAddress",				-0xc,	"415648***4C8BF24C8D***BA****E8****488BD84885C075*B8****"},
	{0, "DbgkpSendApiMessageLpc",				-0x19,	"4889******65********418AF0488BFA488BD9488B*****4584C074*488BCDE8****"	},
	{0, "DbgkpSendErrorMessage",				-0x30,	"33D24889***4D8BE0488D**448D**E8****33C04889***65********8844**4C89***4D8B*****498BCFE8****488BC8"},
	
	// for debug hook
	{0, "NtCreateDebugObject",					-0x11,	"48******418BF1448BF2488BF965********8A88****84C974*48*********483BFA480F42D7488B02488902"},
	{0, "NtWaitForDebugEvent",					-0x8c,	"488B***488B084889***488D***4889***49*********498B**4889***EB*49*********"},
	{0, "NtDebugActiveProcess",					-0x33,	"4883****BA****4883****4C******408A*****488D***4889***448ACDC744******E8****"},
	{0, "NtDebugContinue",						-0x4e,	"0F1002F30F****81*****74*81*****7E*81*****7E*81*****74*81*****7E*81*****7E*B8****E9****"},
	{0, "DbgkForwardException",					-0x78,	"0F*****65********8B88****F6**75*488B*****4532F64885DB0F*****4084FF0F*****"},
	{0,	"",										0xffff, ""} 
};

VOID Init_g_SymbolOffset_Win10_18363() {

	// EPROCESS
	g_NtSymbolOffset.EPROCESS_ProcessLock = 0x2e0;
	g_NtSymbolOffset.EPROCESS_RundownProtect = 0x300;
	g_NtSymbolOffset.EPROCESS_Flags = 0x30c;
	g_NtSymbolOffset.EPROCESS_DebugPort = 0x420;
	g_NtSymbolOffset.EPROCESS_ExceptionPortData = 0x358;

	// ETHREAD
	g_NtSymbolOffset.ETHREAD_Teb = 0xf0;
	g_NtSymbolOffset.ETHREAD_MiscFlags = 0x74;
	g_NtSymbolOffset.ETHREAD_ApcState_Process = 0x98 + 0x20;
	g_NtSymbolOffset.ETHREAD_KernelApcDisable = 0x1e4;
	g_NtSymbolOffset.ETHREAD_ApcStateIndex = 0x24a;
	g_NtSymbolOffset.ETHREAD_StartAddress = 0x620;
	g_NtSymbolOffset.ETHREAD_RundownProtect = 0x6c8;
	g_NtSymbolOffset.ETHREAD_CrossThreadFlags = 0x6e0;
}
