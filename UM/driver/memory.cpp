#include <Windows.h>
#include <memory>
#include "memory.hpp"
#include "driver.hpp"
#include "../utilities/util.hpp"
#include "../security/crypt.hpp"

ULONG64 Memory::getProcessId(const char* processName) 
{
	MEMORY_STRUCT instructions = { 0 };
	instructions.type = 5;
	instructions.magic = 0xBEEF;
	// we're using module_name in lieu of the process_name for now (const char*)
	instructions.module_name = processName;

	Driver::call_hook(&instructions);

	// also using m->base_address for pID.. (ULONG64)
	ULONG64 pID = instructions.base_address;

	processId = static_cast<uint32_t>(pID);

	return pID;
}

ULONG64 Memory::getModuleBaseAddress(const char* moduleName) 
{
	MEMORY_STRUCT instructions = { 0 };
	instructions.type = 6;
	instructions.magic = 0xBEEF;
	instructions.usermode_pid = processId;
	instructions.module_name = moduleName;

	Driver::call_hook(&instructions);

	ULONG64 base = instructions.base_address;

	return base;
}
