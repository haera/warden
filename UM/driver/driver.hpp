#pragma once
#include <Windows.h>
#include <cstdint>

using NtUserLoadKeyboardLayoutEx_t = PVOID(__fastcall*)(void* a1, unsigned int a2, void* a3, void* a4, void* a5, void* a6, int a7, int a8);
inline NtUserLoadKeyboardLayoutEx_t FunctionPTR;
inline uint64_t kernel_addr;

typedef struct _MEMORY_STRUCT
{
	BYTE type;
	LONG usermode_pid;
	LONG target_pid;
	const char* module_name;
	ULONG64 base_address;
	void* address;
	LONG size;
	void* output;
	ULONG magic = 0xBEEF;
} MEMORY_STRUCT;

namespace Driver
{
	void* kernel_control_function();

	bool load_kernel_addr();

	PVOID call_hook(MEMORY_STRUCT* instructions);
};