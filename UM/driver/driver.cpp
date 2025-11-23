#include "driver.hpp"
#include "../security/crypt.hpp"
#include "../security/lazy_functions.hpp"

//using NtUserLoadKeyboardLayoutEx_t = int64_t(__fastcall*)(void* a1, unsigned int a2, void* a3, void* a4, void* a5, void* a6, int a7, int a8);

void* Driver::kernel_control_function()
{
	// win32u.dll is a link for System calls between UM and KM
	HMODULE hModule = Lazy::LI_LoadLibraryA((skCrypt("win32u.dll")));
	if (!hModule)
		return nullptr;

	FunctionPTR = (NtUserLoadKeyboardLayoutEx_t)Lazy::LI_GetProcAddress(
		Lazy::LI_GetModuleHandleA(skCrypt("win32u.dll")),
		skCrypt("NtUserLoadKeyboardLayoutEx")
	);

	return (void*)FunctionPTR;
}

bool Driver::load_kernel_addr()
{
	DWORD size = sizeof(kernel_addr);
	auto st = Lazy::LI_RegGetValueW(
		HKEY_LOCAL_MACHINE, 
		L"SOFTWARE\\RegisteredApplications",
		L"Warden", 
		RRF_RT_REG_BINARY, 
		nullptr, 
		&kernel_addr, 
		&size
	);

	// this code is hilarious
	return st == ERROR_SUCCESS;
}

PVOID Driver::call_hook(MEMORY_STRUCT* payload) 
{
	if (!FunctionPTR || !payload)
		return 0;

	/* 
	calls func via the simple rop below::
		- NtUserLoadKeyboardLayoutEx_t a3(RDX) as our MEMORY_STRUCT* instructions
		- a1(RCX) as our kernel routine addr used in "push rcx; ret" gadget
	*/
	void *kernel_routine = reinterpret_cast<void*>(kernel_addr);
	void *comm			 = reinterpret_cast<void*>(payload);

	// NtUserCreateDesktopEx(kernel_routine, comm, ...)
	PVOID result = FunctionPTR(
		kernel_routine, 
		1234,
		comm,
		(void*)0xBEEFBEEFDEADDEAD, 
		(void*)0x55555, 
		(void*)0x66666, 
		7, 
		8
	);

	return result;
}