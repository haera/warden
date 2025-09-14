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

	okay("warden loaded successfully.");
}

int main() 
{
	info("warden loading...");

	Initialize();

	return 0;
}