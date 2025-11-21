#pragma once
#include "imports.hpp"

#define RVA(addr, size) ((PBYTE)(addr + *(DWORD*)(addr + ((size) - 4)) + size))

namespace mem
{
	uintptr_t get_system_module_base(const char* module_name)
	{
		ULONG size = 0;
		ZwQuerySystemInformation(SystemModuleInformation, nullptr, 0, &size);
		if (!size)
			return 0;

		PVOID buffer = ExAllocatePool(NonPagedPool, size);
		if (!buffer)
			return 0;

		if (!NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, buffer, size, &size))) 
		{
			ExFreePoolWithTag(buffer, 0);
			return 0;
		}

		PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)buffer;
		uintptr_t base = 0;

		for (ULONG i = 0; i < modules->NumberOfModules; ++i) 
		{
			const char* name = (const char*)(modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName);
			if (_stricmp(name, module_name) == 0) 
			{
				base = (uintptr_t)modules->Modules[i].ImageBase;
				break;
			}
		}

		ExFreePoolWithTag(buffer, 'ldmB');
		return base;
	}

	PVOID GetSystemBaseModuleExport(const char* module_name, LPCSTR routine_name)
	{
		PVOID base_module = (PVOID)mem::get_system_module_base(module_name);
		if (!base_module) return NULL;
		return RtlFindExportedRoutineByName(base_module, routine_name);
	}

	bool WriteMemory(void* address, void* buffer, size_t size)
	{
		return RtlCopyMemory(address, buffer, size) != 0;
	}

	bool WriteToReadOnlyMemory(void* address, void* buffer, size_t size) {
		PMDL Mdl = IoAllocateMdl(address, static_cast<ULONG>(size), FALSE, FALSE, NULL);

		if (!Mdl) return false;

		MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
		PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
		MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);

		WriteMemory(Mapping, buffer, size);

		MmUnmapLockedPages(Mapping, Mdl);
		MmUnlockPages(Mdl);
		IoFreeMdl(Mdl);

		return true;
	}

	bool Hook(void* destination)
	{
		if (!destination) return false;

		PVOID* dxgk_routine = reinterpret_cast<PVOID*>(mem::GetSystemBaseModuleExport("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtSetCompositionSurfaceAnalogExclusive"));
		if (!dxgk_routine) return false;

		BYTE orignal_shell_code[] = {
		0x90,										// nop
		0x90,										// nop 
		0x90,										// nop
		0x48, 0xB8,									// mov rax, 
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,		// [xxx]
		0x90,										// nop
		0x90,										// nop
		0x48, 0xB8,									// mov rax, 
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,		// [xxx]
		0xFF, 0xE0,									// jmp rax // d0 for call
		0xCC,										//int3									

		};

		BYTE start[]{ 0x48, 0xB8 }; // mov rax,
		BYTE end[]{ 0xFF, 0xE0, 0xCC }; // jmp rax

		RtlSecureZeroMemory(&orignal_shell_code, sizeof(orignal_shell_code));

		memcpy((PVOID)((ULONG_PTR)orignal_shell_code), &start, sizeof(start));

		uintptr_t test_address = reinterpret_cast<uintptr_t>(destination);

		memcpy((PVOID)((ULONG_PTR)orignal_shell_code + sizeof(start)), &test_address, sizeof(void*));
		memcpy((PVOID)((ULONG_PTR)orignal_shell_code + sizeof(start) + sizeof(void*)), &end, sizeof(end));

		WriteToReadOnlyMemory(dxgk_routine, &orignal_shell_code, sizeof(orignal_shell_code));

		return true;
	}

	ULONG64 GetModuleBaseFor64BitProcess(PEPROCESS proc, UNICODE_STRING module_name)
	{
		PPEB pPeb = PsGetProcessPeb(proc);
		if (!pPeb) return 0;

		KAPC_STATE state;

		KeStackAttachProcess(proc, &state);

		PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

		if (!pLdr)
		{
			KeUnstackDetachProcess(&state);
			return 0;
		}

		for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->ModuleListLoadOrder.Flink; list != &pLdr->ModuleListLoadOrder; list = (PLIST_ENTRY)list->Flink)
		{
			PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
			if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) == 0)
			{
				ULONG64 baseAddr = (ULONG64)pEntry->DllBase;
				KeUnstackDetachProcess(&state);
				return baseAddr;
			}
		}

		KeUnstackDetachProcess(&state);

		return 0;
	}

	// handles both narrow and wchar_t char strings -- winapi likes to return both ANSI and unicode
	template <typename str_type, typename str_type_2>
	__forceinline bool crt_strcmp(str_type str, str_type_2 in_str, bool two)
	{
		if (!str || !in_str)
			return false;

		wchar_t c1, c2;
#define to_lower(c_char) ((c_char >= 'A' && c_char <= 'Z') ? (c_char + 32) : c_char)
		
		do
		{
			c1 = *str++; c2 = *in_str++;
			c1 = to_lower(c1); c2 = to_lower(c2);

			if (!c1 && (two ? !c2 : 1))
				return true;

		} while (c1 == c2);

		return false;
	}

	// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/2110%2021H2%20(November%202021%20Update)/_EPROCESS
	ULONG64 find_pid_by_name(const wchar_t* process_name)
	{
		if (process_name == NULL)
			return 0;

		// get the initial system process usually "system" process
		PEPROCESS sys_process = PsInitialSystemProcess;
		PEPROCESS cur_entry = sys_process;

		if (sys_process == NULL)
			return 0;

		CHAR image_name[15];
		ULONG64 process_id = 0;

		// iter thru all processes, starting from "system" proc
		do
		{
			// cpy process name from the EPROCESS structure to image_name
			RtlCopyMemory((PVOID)(&image_name), (PVOID)((uintptr_t)cur_entry + ImageFileName) /*EPROCESS->ImageFileName*/, sizeof(image_name));

			if (crt_strcmp(image_name, process_name, true))
			{
				DWORD active_threads;

				// cpy # of active threads from the EPROCESS struct
				RtlCopyMemory((PVOID)&active_threads, (PVOID)((uintptr_t)cur_entry + ActiveThreads) /*EPROCESS->ActiveThreads*/, sizeof(active_threads));

				if (active_threads) {
					// if there are active threads in the process, get its ID
					process_id = (ULONG64)PsGetProcessId(cur_entry);
					break;
				}
			}

			// move to the next process in the list of active processes
			PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(cur_entry)+ActiveProcessLinks) /*EPROCESS->ActiveProcessLinks*/;
			// check for invalid list entry
			if (list == NULL || list->Flink == NULL)
				break;

			// mov current entry to next process
			cur_entry = (PEPROCESS)((uintptr_t)list->Flink - ActiveProcessLinks);

			// check for circular / broken list?
			if (cur_entry == sys_process || cur_entry == NULL)
				break;

		} while (cur_entry != sys_process); // loop till we're back at system process

		return process_id;
	}

	uintptr_t sig_scan(const char* signature, const uintptr_t base)
	{
		if (!base || !signature)
			return 0;

		// Parse pattern like "48 8B ?? ?? ?? 89"
		auto pattern_to_bytes = [](const char* pattern, unsigned char* bytes, char* mask, SIZE_T& out_len) noexcept
		{
			SIZE_T i = 0;
			while (*pattern && i < 256)
			{
				if (*pattern == ' ')
				{
					++pattern;
					continue;
				}

				if (*pattern == '?')
				{
					++pattern;
					if (*pattern == '?') ++pattern;
					bytes[i] = 0;
					mask[i] = '?';
				}
				else
				{
					ULONG val = 0;
					char temp[3] = { pattern[0], pattern[1], 0 };
					RtlCharToInteger(temp, 16, &val);
					bytes[i] = static_cast<unsigned char>(val);
					mask[i] = 'x';
					pattern += 2;
				}

				++i;
			}
			out_len = i;
		};

		unsigned char sig_bytes[256];
		char sig_mask[256];
		SIZE_T sig_len = 0;
		pattern_to_bytes(signature, sig_bytes, sig_mask, sig_len);

		if (!sig_len)
			return 0;

		// No PE parsing: naive full scan of 2MB range
		auto* region = reinterpret_cast<unsigned char*>(base);
		const SIZE_T scan_size = 0x200000; // 2MB max

		for (SIZE_T i = 0; i < scan_size - sig_len; ++i)
		{
			bool matched = true;
			for (SIZE_T j = 0; j < sig_len; ++j)
			{
				if (sig_mask[j] == 'x' && region[i + j] != sig_bytes[j])
				{
					matched = false;
					break;
				}
			}

			if (matched)
				return reinterpret_cast<uintptr_t>(&region[i]);
		}

		return 0;
	}

}