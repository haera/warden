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

	Memory() {
		usermode_pid = Lazy::LI_GetCurrentProcessId();
	}

public:
	ULONG64 getProcessId(const char* processName);
	ULONG64 getModuleBaseAddress(const char* moduleName);
	std::string ReadString(uintptr_t address, size_t max_length);
	bool GetBaseAddresses(uintptr_t& baseClient, uintptr_t& baseEngine);

	template<typename T>
	T Read(UINT_PTR readAddress);

	template<typename T>
	bool Write(uint64_t writeAddress, T buffer);

	inline void ReadRaw(uintptr_t address, void* buffer, size_t size);

};


template <typename T>
T Memory::Read(UINT_PTR readAddress)
{
	T response{};
	MEMORY_STRUCT instructions = { 0 };
	instructions.type = 3;
	instructions.magic = 0x1337;
	instructions.usermode_pid = usermode_pid;
	instructions.target_pid = processId;
	instructions.address = reinterpret_cast<void*>(readAddress);
	instructions.size = sizeof(T);
	instructions.output = &response;

	Driver::callHook(&instructions);

	return response;
}

template<typename T>
bool Memory::Write(uint64_t writeAddress, T buffer)
{
	MEMORY_STRUCT instructions = { 0 };
	instructions.type = 4;
	instructions.magic = 0x1337;
	instructions.usermode_pid = usermode_pid;
	instructions.target_pid = processId;
	instructions.address = reinterpret_cast<void*>(writeAddress);
	instructions.size = sizeof(T);
	instructions.output = &buffer;

	Driver::callHook(&instructions);

	return true;
}

// reads specified number of bytes from given address into the buffer
void Memory::ReadRaw(uintptr_t address, void* buffer, size_t size) {
	MEMORY_STRUCT instructions = { 0 };
	instructions.type = 3;
	instructions.magic = 0x1337;
	instructions.usermode_pid = usermode_pid;
	instructions.target_pid = processId;
	instructions.address = reinterpret_cast<void*>(address);
	instructions.size = static_cast<LONG>(size);
	instructions.output = buffer;

	Driver::callHook(&instructions);
}