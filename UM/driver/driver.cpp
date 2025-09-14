#include "driver.hpp"
#include "../security/crypt.hpp"
#include "../security/lazy_functions.hpp"

//PVOID(__fastcall* FunctionPTR)(PVOID a1, unsigned int a2, PVOID a3, unsigned int a4, PVOID a5) = nullptr;

// essentially NtSetCompositionSurfaceAnalogExclusive(v1, v2, v3, ...)
void* Driver::kernel_control_function()
{
	// win32u.dll is a link for System calls between UM and KM
	HMODULE hModule = Lazy::LI_LoadLibraryA((skCrypt("win32u.dll")));


	if (!hModule)
		return nullptr;

	void* func = reinterpret_cast<void*>(Lazy::LI_GetProcAddress(hModule, (skCrypt("NtSetCompositionSurfaceAnalogExclusive"))));

	*(PVOID*)&FunctionPTR = Lazy::LI_GetProcAddress(
		Lazy::LI_GetModuleHandleA(skCrypt("win32u.dll")),
		skCrypt("NtSetCompositionSurfaceAnalogExclusive")
	);

	return func;
}

PVOID Driver::callHook(MEMORY_STRUCT* instructions) 
{
	if (!FunctionPTR || !instructions)
		return 0;

	using tFunction = PVOID(__fastcall*)(PVOID, UINT, PVOID, UINT, PVOID);

	// call function thru tFunction with arg[2] as our MEMORY_STRUCT* instructions
	PVOID result = reinterpret_cast<tFunction>(FunctionPTR)(NULL, 0, static_cast<PVOID>(instructions), 0, NULL);

	return result;
}