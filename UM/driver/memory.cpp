#include <Windows.h>
#include <memory>
#include "memory.hpp"
#include "driver.hpp"
#include "../utilities/util.hpp"
#include "../security/crypt.hpp"

ULONG64 Memory::getProcessId(const char* processName) 
{
	MEMORY_STRUCT payload = { 0 };
	payload.type = 5;
	payload.magic = 0xBEEF;
	// we're using module_name in lieu of the process_name for now (const char*)
	payload.module_name = processName;

	Driver::call_hook(&payload);

	// also using m->base_address for pID.. (ULONG64)
	ULONG64 pID = payload.base_address;

	processId = static_cast<uint32_t>(pID);

	return pID;
}

ULONG64 Memory::getModuleBaseAddress(const char* moduleName) 
{
	MEMORY_STRUCT payload = { 0 };
	payload.type = 6;
	payload.magic = 0xBEEF;
	payload.usermode_pid = processId;
	payload.module_name = moduleName;

	Driver::call_hook(&payload);

	ULONG64 base = payload.base_address;

	return base;
}
