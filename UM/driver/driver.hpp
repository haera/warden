#pragma once
#include <Windows.h>
#include <cstdint>

inline PVOID(__fastcall* FunctionPTR)(PVOID a1, unsigned int a2, PVOID a3, unsigned int a4, PVOID a5);

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
	ULONG magic;
} MEMORY_STRUCT;

namespace Driver
{
	void* kernel_control_function();

	PVOID callHook(MEMORY_STRUCT* instructions);
};