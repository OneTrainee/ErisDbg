FunctionSignatureItem functionTable_Win10_19045[] = {
	{0,	"ObDuplicateObject",					-0x1c,	"48******4833C44889*****8BBD****0F57C0498BF04889***4889***33D241*****488D*****0F11**"},
	{0,	"PsSynchronizeWithThreadInsertion",		-0x10,	"48******F0****488B01A8*74*E8****488BCBE8****48***5BC3"},
	{0,	"PsSuspendThread",						-0x15,	"4C8BF2488BF98364***65********4889***66FF*****4C8D*****4C89***498BCFE8****"},
	{0,	"PsGetNextProcessThread",				-0x31,	"448BFB448BF36641*******488D*****33D2488BCDE8****4885FF0F*****488B*****493BF5"},
	{0,	"PsResumeThread",						-0x28,	"75*4C8B*****B8****418B*****85C874*0F***0F*****4885DB74*"},
	{0, "PsQuerySystemDllInfo",					0x0,	"4863C148******488B04C14885C074*4883***74*48***C3CC" },
	{0, "PsFreezeProcess",						-0x10,	"48***8B81****8ADA488BF9A8*0F*****E8****8B8F****F6**0F*****65********85C075*F787********0F*****"},
	{0, "KeLeaveCriticalRegionThread",			0x0,	"48***6683******75*488D*****48390075*48***C3"},
	{0,	"PsThawProcess"	,						-0x16,	"408AF2488BF965********4C89***84D20F*****4883******74*8B81****A8*75*E8****"},
	{0, "MmGetFileNameForAddress",				-0xb,	"5657415648***8360**4C8D**4C8BF2BA****E8****488BD84885C0"},
	{0, "DbgkpSendApiMessageLpc",				-0x8,	"48******48******4833C44889******65********418AF0488BFA488BD9488B*****4584C074*488BCD"	},
	{0, "DbgkpSendErrorMessage",				-0xc,	"41564157488D***48******48******4833C44889**8BFA8954**33D2"},
	// for debug hook
	{0, "NtCreateDebugObject",					-0x34,	"448A*****4584D274*48*********483BF9480F42CF488B0148890148***F7*****74*"},
	{0, "NtWaitForDebugEvent",					-0x8,	"4156415748******48******4833C44889******498BF1408AFA8854**488BD94C89***"},
	{0, "NtDebugActiveProcess",					-0x29,	"4C******4983***408A*****498D**4983***448ACD4989**C744******E8****85C00F*****65********488B******"},
	{0, "NtDebugContinue",						-0x1f,	"0F11**65********448A*****4584C974*48*********483BD0480F42C28A000F1002F30F****81*****74*"},
	{0, "DbgkForwardException",					-0x2c,	"4883****458AF8408AFA4C8BE133D2488D***41*****E8****4584FF0F*****"},

	{0,	"",										0xffff, ""} 
};

VOID Init_g_SymbolOffset_Win10_19045() {

	// EPROCESS
	g_NtSymbolOffset.EPROCESS_ProcessLock = 0x438;
	g_NtSymbolOffset.EPROCESS_RundownProtect = 0x458;
	g_NtSymbolOffset.EPROCESS_Flags = 0x460;
	g_NtSymbolOffset.EPROCESS_DebugPort = 0x578;
	g_NtSymbolOffset.EPROCESS_ExceptionPortData = 0x4b0;

	// ETHREAD
	g_NtSymbolOffset.ETHREAD_Teb = 0xf0;
	g_NtSymbolOffset.ETHREAD_MiscFlags = 0x74;
	g_NtSymbolOffset.ETHREAD_ApcState_Process = 0x98 + 0x20;
	g_NtSymbolOffset.ETHREAD_KernelApcDisable = 0x1e4;
	g_NtSymbolOffset.ETHREAD_ApcStateIndex = 0x24a;
	g_NtSymbolOffset.ETHREAD_StartAddress = 0x450;
	g_NtSymbolOffset.ETHREAD_RundownProtect = 0x4f8;
	g_NtSymbolOffset.ETHREAD_CrossThreadFlags = 0x510;
}
