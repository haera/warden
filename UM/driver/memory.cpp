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
	instructions.magic = 0x1337;
	// we're using module_name in lieu of the process_name for now (const char*)
	instructions.module_name = processName;

	Driver::callHook(&instructions);

	// also using m->base_address for pID.. (ULONG64)
	ULONG64 pID = instructions.base_address;

	processId = static_cast<uint32_t>(pID);

	return pID;
}

ULONG64 Memory::getModuleBaseAddress(const char* moduleName) 
{
	MEMORY_STRUCT instructions = { 0 };
	instructions.type = 6;
	instructions.magic = 0x1337;
	instructions.usermode_pid = processId;
	instructions.module_name = moduleName;

	Driver::callHook(&instructions);

	ULONG64 base = instructions.base_address;

	return base;
}

std::string Memory::ReadString(uintptr_t address, size_t max_length) 
{
	std::string result;
	for (size_t i = 0; i < max_length; ++i) {
		char c = Read<char>(address + i);
		if (c == '\0')
			break;

		result.push_back(c);
	}
	return result;
}