#include "mem.hpp"
#include "imports.hpp"
#include <cstdint>

/*
o_ApiSetEditionCreateWindowStationEntryPoint => qword_257F10
	__int64 (__fastcall *qword_257F10)(_QWORD, _QWORD, _QWORD, _QWORD, _DWORD, _QWORD, _QWORD, _DWORD)

hk_ApiSetEditionCreateWindowStationEntryPoint => swapped internal qword_257F10 dptr
*/
INT64(__fastcall* o_ApiSetEditionCreateWindowStationEntryPoint)(PVOID a1, ULONG a2, PVOID a3, ULONG a4, INT a5, PVOID comm, PVOID a7, INT a8);

INT64 __fastcall hk_ApiSetEditionCreateWindowStationEntryPoint(PVOID a1, ULONG a2, PVOID a3, ULONG a4, INT a5, PVOID comm, PVOID a7, INT a8)
{
	if (ExGetPreviousMode() != UserMode)
	{
		return o_ApiSetEditionCreateWindowStationEntryPoint(a1, a2, a3, a4, a5, comm, a7, a8);
	}

	if (comm)
	{

		MEMORY_STRUCT* m = (MEMORY_STRUCT*)comm;

		DebugPrint("[+] greetings.");

		if (m->magic != 0x1337 || !m->type)
		{
			return o_ApiSetEditionCreateWindowStationEntryPoint(a1, a2, a3, a4, a5, comm, a7, a8);
		}

		if (m->type == 1)
		{
			// simple check if driver is communicating
			PEPROCESS usermode_process;
			if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)m->usermode_pid, &usermode_process)))
			{
				m->output = (void*)0x9999;
				DebugPrint("[+] m->type 1 comm check: %x", m->output);
			}

			return 9999;
		}
	}

	return o_ApiSetEditionCreateWindowStationEntryPoint(a1, a2, a3, a4, a5, comm, a7, a8);
}


/*
	um: 
		win32u.dll!NtUserCloseDesktop(&a1);
	km: 
		win32kbase!NtUserCreateWindowStation
			-> win32kbase!ApiSetEditionCreateWindowStationEntryPoint (E8 ? ? ? ? 48 83 C4 48 C3 CC CC CC CC CC CC CC CC 48 8B C4 48 89 58 08 48 89 68 10)

	- NtUserCreateWindowStation is exported so it will be used for usermode syscall.. it internally calls ApiSetEditionCreateWindowStationEntryPoint (not exported)
	- ApiSetEditionCreateWindowStationEntryPoint's fptr (qword_257F10) will now redirect to JMP RCX
*/

/*
INT64 __fastcall NtSetCompositionSurfaceAnalogExclusive(PVOID a1, PVOID a2, PVOID SectionInfo, PVOID a4, PVOID a5)
{
	if (ExGetPreviousMode() != UserMode)
	{
		return Qword_ptrOriginal(a1, a2, SectionInfo, a4, a5);
	}

	if (SectionInfo)
	{
		MEMORY_STRUCT* m = (MEMORY_STRUCT*)SectionInfo;

		if (m->magic != 0x1337)
		{
			return Qword_ptrOriginal(a1, a2, SectionInfo, a4, a5);
		}

		if (!m->type)
		{
			return Qword_ptrOriginal(a1, a2, SectionInfo, a4, a5);
		}

		if (m->type == 1)
		{

			// simple check if driver is communicating

			PEPROCESS usermode_process;
			if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)m->usermode_pid, &usermode_process)))
			{
				m->output = (void*)0x9999;
				//DebugPrint("[+] m->type 1 comm check: %x", m->output);
			}

			return 9999;
		}
		else if (m->type == 3)
		{
			//Read process memory
			if (!m->address || !m->size || !m->usermode_pid || !m->target_pid) return STATUS_INVALID_PARAMETER_1;

			PEPROCESS usermode_process;
			if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)m->usermode_pid, &usermode_process)))
			{
				PEPROCESS target_process;
				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)m->target_pid, &target_process)))
				{
					SIZE_T bytes = 0;

					NTSTATUS x = MmCopyVirtualMemory(target_process, m->address, usermode_process, m->output, m->size, UserMode, &bytes);

					if (NT_SUCCESS(x))
					{
						return 0;
					}
					else
						return 1;
				}
				else return 2;
			}
			else return 3;
		}
		else if (m->type == 4)
		{
			//Write process memory
			if (!m->address || !m->size || !m->output || !m->usermode_pid || !m->target_pid) return STATUS_INVALID_PARAMETER_1;

			PEPROCESS usermode_process;
			if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)m->usermode_pid, &usermode_process)))
			{
				PEPROCESS target_process;
				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)m->target_pid, &target_process)))
				{
					SIZE_T bytes = 0;

					NTSTATUS x = MmCopyVirtualMemory(usermode_process, m->output, target_process, m->address, m->size, UserMode, &bytes);

					if (NT_SUCCESS(x))
						return 0;
					else
						return 1;
				}
				else return 2;
			}
			else return 3;
		}
		else if (m->type == 5) {
			ANSI_STRING x;
			UNICODE_STRING process_name;
			// we're using module_name in lieu of the process_name for now
			RtlInitAnsiString(&x, m->module_name);
			RtlAnsiStringToUnicodeString(&process_name, &x, TRUE);


			ULONG64 processId = 0;
			processId = mem::FindProcessIdByName(process_name.Buffer);
			// same with base_address... figure out smarter serialization pls
			m->base_address = processId;

			return 0;
		}
		else if (m->type == 6)
		{
			ANSI_STRING x;
			UNICODE_STRING module;
			RtlInitAnsiString(&x, m->module_name);
			RtlAnsiStringToUnicodeString(&module, &x, TRUE);

			PEPROCESS usermode;
			PsLookupProcessByProcessId((HANDLE)m->usermode_pid, &usermode);

			ULONG64 base_address = NULL;
			base_address = mem::GetModuleBaseFor64BitProcess(usermode, module);
			m->base_address = base_address;
			RtlFreeUnicodeString(&module);

			return 0;
		}
		else
		{
			return Qword_ptrOriginal(a1, a2, SectionInfo, a4, a5);
		}

	}

	return Qword_ptrOriginal(a1, a2, SectionInfo, a4, a5);
}
*/

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(registry_path);

	//Hook the function to NtSetCompositionSurfaceAnalogExclusive
	//mem::Hook(&NtSetCompositionSurfaceAnalogExclusive);

	HANDLE pid = (HANDLE)mem::FindProcessIdByName(L"explorer.exe");
	if (!pid)
	{
		DebugPrint("[X] explorer not found\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	DebugPrint("[+] pid: %d\n", pid);

	PEPROCESS process;
	PsLookupProcessByProcessId(pid, &process);

	KAPC_STATE state;
	KeStackAttachProcess(process, &state);

	auto win32kbase = mem::get_system_module_base("win32kbase.sys");
	if (!win32kbase)
	{
		DebugPrint("[X] win32kbase not found\n");	
		KeUnstackDetachProcess(&state);
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	DebugPrint("[+] win32kbase: 0x%p\n", win32kbase);

	auto signature_addr = mem::sig_scan("E8 ? ? ? ? 48 83 C4 48 C3 CC CC CC CC CC CC CC CC 48 8B C4 48 89 58 08 48 89 68 10", (uintptr_t)win32kbase);
	if (!signature_addr)
	{
		DebugPrint("[X] could not find signature_addr\n");
		KeUnstackDetachProcess(&state);
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	DebugPrint("[+] found signature_addr at 0x%p\n", signature_addr);

	auto data_ptr = RVA(RVA(signature_addr, 5) + 0x60, 7);
	DebugPrint("[+] function_ptr = 0x%p\n", data_ptr);


	// find our "push rcx; ret" gadget:
	auto gadget_addr = mem::sig_scan("51 C3", (uintptr_t)win32kbase);
	if (!gadget_addr)
	{
		DebugPrint("[X] could not find gadget_addr\n");
		KeUnstackDetachProcess(&state);
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	DebugPrint("[+] found gadget_addr at 0x%p\n", gadget_addr);

	/*
	void* InterlockedExchangePointer(void** Target, void* Source) {
		void* oldPointer = *Target;
		*Target = Source;
		return oldPointer;
	} // its the above but atomic. notice: uses xchg, could be flagged
	*/
	o_ApiSetEditionCreateWindowStationEntryPoint =
		(INT64(__fastcall*)(PVOID, ULONG, PVOID, ULONG, INT, PVOID, PVOID, INT)) // template please
		_InterlockedExchangePointer(
			(PVOID*)data_ptr, // *qword_257F10
			(PVOID)hk_ApiSetEditionCreateWindowStationEntryPoint // bad naming convention, its really what was in qword_257F10
		);

	DebugPrint("[+] o_ApiSetEditionCreateWindowStationEntryPoint = 0x%p\n", o_ApiSetEditionCreateWindowStationEntryPoint);
	DebugPrint("[+] hk_ApiSetEditionCreateWindowStationEntryPoint = 0x%p\n", hk_ApiSetEditionCreateWindowStationEntryPoint);

	/*
	auto win32kfull = mem::get_system_module_base("win32kfull.sys");
	if (!win32kfull)
	{
		DebugPrint("[X] win32kfull not found\n");
		KeUnstackDetachProcess(&state);
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	DebugPrint("[+] win32kfull: 0x%p\n", win32kfull);
	
	// JMP RCX
	auto gadget_addr = mem::sig_scan("FF E1", (uintptr_t)win32kfull);
	if (!gadget_addr)
	{
		DebugPrint("[X] could not find gadget_addr\n");
		KeUnstackDetachProcess(&state);
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	DebugPrint("[+] found gadget_addr at 0x%p\n", gadget_addr);
	*/






	KeUnstackDetachProcess(&state);

	DebugPrint("HOOKED\n");
	return STATUS_SUCCESS;
}