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

	/*
	void* func = reinterpret_cast<void*>(Lazy::LI_GetProcAddress(hModule, (skCrypt("NtSetCompositionSurfaceAnalogExclusive"))));

	*(PVOID*)&FunctionPTR = Lazy::LI_GetProcAddress(
		Lazy::LI_GetModuleHandleA(skCrypt("win32u.dll")),
		skCrypt("NtSetCompositionSurfaceAnalogExclusive")
	);
	*/

	auto NtUserCreateWindowStation = (NtUserCreateWindowStation_t)Lazy::LI_GetProcAddress(
		Lazy::LI_GetModuleHandleA(skCrypt("win32u.dll")),
		skCrypt("NtUserCreateWindowStation")
	);

	FunctionPTR = NtUserCreateWindowStation;

	return (void*)FunctionPTR;
}

void Driver::resolve_gadget(uintptr_t kernel_routine)
{
	kernel_addr = reinterpret_cast<void*>(kernel_routine);
}

PVOID Driver::call_hook(MEMORY_STRUCT* instructions) 
{
	if (!FunctionPTR || !instructions)
		return 0;

	// call function thru NtUserCreateWindowStation_t a1 (RCX) as our MEMORY_STRUCT* instructions
	void* comm = reinterpret_cast<void*>(instructions);
	PVOID result = FunctionPTR((void*)0xAAAABBBBCCCCDDDD, 0xEEEEFFFFABCDEFFF, 1336, 444, 0xDEEBBEEBFEEFFAAF, comm, 0xABCD12EF, 888);

	return result;
}