#pragma once
#include <Windows.h>
#include <cstdint>

//inline PVOID(__fastcall* FunctionPTR)(PVOID a1, unsigned int a2, PVOID a3, unsigned int a4, PVOID a5);
using NtUserCreateWindowStation_t = PVOID(__fastcall*)(void* a1, ACCESS_MASK a2, int a3, int a4, int a5, void* a6, __int64 a7, int a8);
inline NtUserCreateWindowStation_t FunctionPTR;
inline void* kernel_addr;

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

	void resolve_gadget(uintptr_t kernel_routine);

	PVOID call_hook(MEMORY_STRUCT* instructions);
};