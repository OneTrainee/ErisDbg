#pragma once
#define __EPT_PAGE_HOOK 'Hook'
#define __EPT_PAGE_UNHOOK 'unHk'

enum VmCall
{
	CallExitVT,
	CallEptHook,
	CallEptUnHook,
};