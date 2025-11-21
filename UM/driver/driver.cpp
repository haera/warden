#include "driver.hpp"
#include "../security/crypt.hpp"
#include "../security/lazy_functions.hpp"

void* Driver::kernel_control_function()
{
	// win32u.dll is a link for System calls between UM and KM
	HMODULE hModule = Lazy::LI_LoadLibraryA((skCrypt("win32u.dll")));
	if (!hModule)
		return nullptr;

	FunctionPTR = (NtUserCreateDesktopEx_t)Lazy::LI_GetProcAddress(
		Lazy::LI_GetModuleHandleA(skCrypt("win32u.dll")),
		skCrypt("NtUserCreateDesktopEx")
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
		- NtUserCreateDesktopEx_t a2(RDX) as our MEMORY_STRUCT* instructions
		- a1(RCX) as our kernel routine addr used in "push rcx; ret" gadget
	*/
	void *kernel_routine = reinterpret_cast<void*>(kernel_addr);
	void *comm			 = reinterpret_cast<void*>(payload);

	// NtUserCreateDesktopEx(kernel_routine, comm, ...)
	PVOID result = FunctionPTR(
		kernel_routine, 
		comm, 
		(void*)0xDEADBEEF,
		1337,
		0xDEAD,
		0xBEEF
	);

	return result;
}