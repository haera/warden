#include <iostream>
#include "driver/driver.hpp"
#include "driver/memory.hpp"
#include "security/crypt.hpp"
#include "utilities/util.hpp"

void* m_driver_control;
std::shared_ptr<Memory> mem;

void Initialize() 
{
	Lazy::LI_SetConsoleTitleA(skCrypt("warden"));

	/*
		Loading user32 fills out a kernel callback table that is used by KiUserCallbackDispatcher

			.text:18009E69E  mov     rax, gs : 60h; process environment block
			.text:18009E6A7  mov     r9, [rax + 58h]; peb->KernelCallbackTable

		LoadLibrary(skCrypt("user32.dll"));
	*/
	Lazy::LI_LoadLibraryA(skCrypt("user32.dll"));

	m_driver_control = Driver::kernel_control_function();
	if (!m_driver_control) {
		erro("Error: Loading.");
		exit(1);
	}

	mem = std::make_shared<Memory>();

	// gadget logic
	if (!Driver::load_kernel_addr())
	{
		erro("Error: failed to read addr from registry");
		exit(1);
	}
	okay("retrieved kernel_addr from registry: %p", kernel_addr);

	okay("warden loaded successfully.");
}

void Load()
{
	/*
	for (int i = 0; i < 3; ++i) {
		MEMORY_STRUCT* comm = new MEMORY_STRUCT{ 0 };
		comm->type = 1;
		comm->magic = 0xBEEF;
		comm->usermode_pid = GetCurrentProcessId();

		m_driver_control = Driver::call_hook(comm);

		if (comm)
			info("comm->output: %x", comm->output);

		delete comm;

		Sleep(1000);
	}
	*/

	while (!mem->getProcessId(skCrypt("target_proc.exe")))
		Sleep(10);

	info("Found pid: %d", mem->processId);

	if (!mem->getModuleBaseAddress(skCrypt("target_module.dll")))
		Sleep(10);

	info("Found moduleBase: %x", mem->moduleBase);
}

int main() 
{
	info("warden loading...");
	
	Initialize();

	Load();

	return 0;
}