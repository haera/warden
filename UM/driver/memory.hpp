#pragma once
#include <cstdint>
#include <string_view>
#include <Windows.h>
#include "driver.hpp"
#include "../security/lazy_functions.hpp"

class Memory
{
public:
	void* m_driver_control = NULL;
	uint32_t processId = 0;
	DWORD usermode_pid = 0;
	uintptr_t moduleBase = 0;

	Memory() {
		usermode_pid = Lazy::LI_GetCurrentProcessId();
	}

	template <typename T>
	inline T Read(UINT_PTR readAddress)
	{
		T response{};
		MEMORY_STRUCT instructions = { 0 };
		instructions.type = 3;
		instructions.magic = 0xBEEF;
		instructions.usermode_pid = usermode_pid;
		instructions.target_pid = processId;
		instructions.address = reinterpret_cast<void*>(readAddress);
		instructions.size = sizeof(T);
		instructions.output = &response;

		Driver::call_hook(&instructions);

		return response;
	}

	template<typename T>
	inline bool Write(uint64_t writeAddress, T buffer)
	{
		MEMORY_STRUCT instructions = { 0 };
		instructions.type = 4;
		instructions.magic = 0xBEEF;
		instructions.usermode_pid = usermode_pid;
		instructions.target_pid = processId;
		instructions.address = reinterpret_cast<void*>(writeAddress);
		instructions.size = sizeof(T);
		instructions.output = &buffer;

		Driver::call_hook(&instructions);

		return true;
	}

	// reads specified number of bytes from given address into the buffer
	inline void ReadRaw(uintptr_t address, void* buffer, size_t size) {
		MEMORY_STRUCT instructions = { 0 };
		instructions.type = 3;
		instructions.magic = 0xBEEF;
		instructions.usermode_pid = usermode_pid;
		instructions.target_pid = processId;
		instructions.address = reinterpret_cast<void*>(address);
		instructions.size = static_cast<LONG>(size);
		//instructions.size = size;
		instructions.output = buffer;

		Driver::call_hook(&instructions);
	}

	inline ULONG64 getProcessId(const char* processName)
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

	inline ULONG64 getModuleBaseAddress(const char* moduleName)
	{
		MEMORY_STRUCT instructions = { 0 };
		instructions.type = 6;
		instructions.magic = 0xBEEF;
		instructions.usermode_pid = processId;
		instructions.module_name = moduleName;

		Driver::call_hook(&instructions);

		ULONG64 base = instructions.base_address;

		moduleBase = static_cast<uintptr_t>(base);

		return base;
	}
};