#include "mem.hpp"
#include "imports.hpp"
#include <cstdint>

#define FAIL_AND_CLEAN(msg)       \
    do {                          \
        DebugPrint("[X] " msg "\n");   \
        status = STATUS_FAILED_DRIVER_ENTRY; \
        goto cleanup;             \
    } while (0)	

INT64(__fastcall* o_ApiSetEditionCreateDesktopEntryPoint)(PVOID a1, PVOID comm, PVOID a3, UINT a4, INT a5, INT a6);

INT64 __fastcall hk_ApiSetEditionCreateDesktopEntryPoint(PVOID a1, PVOID comm, PVOID a3, UINT a4, INT a5, INT a6)
{
	if (ExGetPreviousMode() != UserMode)
	{
		return o_ApiSetEditionCreateDesktopEntryPoint(a1, comm, a3, a4, a5, a6);
	}

	if (comm)
	{

		MEMORY_STRUCT* m = (MEMORY_STRUCT*)comm;

		if (m->magic != 0x1337 || !m->type)
		{
			return o_ApiSetEditionCreateDesktopEntryPoint(a1, comm, a3, a4, a5, a6);
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

	return o_ApiSetEditionCreateDesktopEntryPoint(a1, comm, a3, a4, a5, a6);
}

/*
	um: 
		win32u.dll!NtUserCreateDesktopEx(&a1);
	km: 
		win32kbase!NtUserCreateDesktopEx
			-> win32kbase!ApiSetEditionCreateDesktopEntryPoint (78 3A 4C 8B 15 ?? ?? ?? ??)

	- NtUserCreateWindowStation is exported so it will be used for usermode syscall.. it internally calls ApiSetEditionCreateDesktopEntryPoint (not exported)
	- ApiSetEditionCreateDesktopEntryPoint's fptr (qword_1C0257E40 on 22H2) will now redirect to "PUSH RCX; RET"
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

	NTSTATUS   status   = STATUS_FAILED_DRIVER_ENTRY;
	PEPROCESS  process  = nullptr;
	KAPC_STATE apc_state{ 0 };
	bool	   attached = false;

	HANDLE pid = (HANDLE)mem::find_pid_by_name(L"explorer.exe");
	if (!pid)
		FAIL_AND_CLEAN("[X] explorer not found\n");
	
	DebugPrint("[+] pid: %d\n", pid);

	NTSTATUS found_proc = PsLookupProcessByProcessId(pid, &process);
	if (!NT_SUCCESS(found_proc))
		FAIL_AND_CLEAN("[X] proc id lookup failed\n");

	KeStackAttachProcess(process, &apc_state);
	attached = true;

	auto win32kbase = mem::get_system_module_base("win32kbase.sys");
	if (!win32kbase)
		FAIL_AND_CLEAN("[X] win32kbase not found\n");

	DebugPrint("[+] win32kbase: 0x%p\n", win32kbase);

	auto signature_addr = mem::sig_scan("78 3A 4C 8B 15 ?? ?? ?? ??", (uintptr_t)win32kbase);
	if (!signature_addr)
		FAIL_AND_CLEAN("[X] could not find signature_addr\n");

	DebugPrint("[+] found signature_addr at 0x%p\n", signature_addr);

	auto data_ptr = RVA(signature_addr + 2, 7); // skip js 0x3C instruction (78 3A)
	DebugPrint("[+] function_ptr = 0x%p\n", data_ptr);

	// find our "push rcx; ret" gadget:
	auto rcx_gadget_addr = mem::sig_scan("51 C3", (uintptr_t)win32kbase);
	if (!rcx_gadget_addr)
		FAIL_AND_CLEAN("[X] could not find rcx_gadget_addr\n");
	
	DebugPrint("[+] found rcx_gadget_addr at 0x%p\n", rcx_gadget_addr);

	/*
	void* InterlockedExchangePointer(void** Target, void* Source) {
		void* oldPointer = *Target;
		*Target = Source;
		return oldPointer;
	} // its the above but atomic. notice: uses xchg, could be flagged
	*/
	o_ApiSetEditionCreateDesktopEntryPoint =
		(INT64(__fastcall*)(PVOID, PVOID, PVOID, UINT, INT, INT)) // template please
		_InterlockedExchangePointer(
			(PVOID*)data_ptr, // *qword_257F10
			(PVOID)rcx_gadget_addr // addr of "push rcx; ret". better pray &hk_ApiSetEditionCreateDesktopEntryPoint is in kernel_routine (RCX) rn!
		);

	DebugPrint("[+] original entrypoint: 0x%p\n", o_ApiSetEditionCreateDesktopEntryPoint);
	DebugPrint("[+] kernel routine: 0x%p\n", hk_ApiSetEditionCreateDesktopEntryPoint);

	// write hk_ApiSetEditionCreateDesktopEntryPoint into registry path
	INT64 kernel_routine_ptr = (INT64)hk_ApiSetEditionCreateDesktopEntryPoint;
	NTSTATUS reg_write_status = RtlWriteRegistryValue(
		RTL_REGISTRY_ABSOLUTE,
		L"\\Registry\\Machine\\SOFTWARE\\RegisteredApplications", 
		L"Warden",
		REG_BINARY,
		&kernel_routine_ptr, 
		sizeof(kernel_routine_ptr)
	);

	if (!NT_SUCCESS(reg_write_status))
		FAIL_AND_CLEAN("[X] RtlWriteRegistryValue failed: = 0x%p\n", reg_write_status);

	/*
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

	status = STATUS_SUCCESS;
	DebugPrint("HOOKED\n");

cleanup:
	if (attached)
		KeUnstackDetachProcess(&apc_state);

	return status;
}