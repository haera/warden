#include "mem.hpp"
#include "imports.hpp"
#include <cstdint>

#define FAIL_AND_CLEAN(msg)    			\
    do {					    	    \
        DebugPrint("[X] " msg "\n");    \
        status = STATUS_FAILED_DRIVER_ENTRY; \
        goto cleanup;		            \
    } while (0)	

INT64(__fastcall* o_NtUserLoadKeyboardLayoutEx)(PVOID a1, UINT a2, PVOID comm, PVOID a4, PVOID a5, PVOID a6, INT a7, INT a8);

INT64 __fastcall hk_NtUserLoadKeyboardLayoutEx(PVOID a1, UINT a2, PVOID comm, PVOID a4, PVOID a5, PVOID a6, INT a7, INT a8)
{
	if (ExGetPreviousMode() != UserMode)
	{
		return o_NtUserLoadKeyboardLayoutEx(a1, a2, comm, a4, a5, a6, a7, a8);
	}

	if (comm)
	{

		MEMORY_STRUCT* m = (MEMORY_STRUCT*)comm;

		if (m->magic != 0xBEEF || !m->type)
		{
			return o_NtUserLoadKeyboardLayoutEx(a1, a2, comm, a4, a5, a6, a7, a8);
		}

		if (m->type == 1)
		{
			// simple check if driver is communicating
			PEPROCESS usermode_process;
			if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)m->usermode_pid, &usermode_process)))
			{
				m->output = (void*)0x9999;
				DebugPrint("[+] m->type 1 comm check: %x, um pid: %ld", m->output, m->usermode_pid);
				DebugPrint("XYZ: hello from hook! return address: 0x%p\n", _ReturnAddress());
			}

			return 9999;
		}
	}

	return o_NtUserLoadKeyboardLayoutEx(a1, a2, comm, a4, a5, a6, a7, a8);
}

/*
	um: 
		win32u.dll!NtUserLoadKeyboardLayoutEx(&a1);
	km: 
		win32k!NtUserLoadKeyboardLayoutEx (

	- NtUserLoadKeyboardLayoutEx is exported so it will be used for usermode syscall.. it internally calls NtUserLoadKeyboardLayoutEx from win32kbase (not exported)
	- NtUserLoadKeyboardLayoutEx's fptr (something qword_??? in win32kbase on 22H2) will now redirect to "PUSH RCX; RET"
*/

__int64 __fastcall hook_proxy(PVOID a1, UINT a2, PVOID comm, PVOID a4, PVOID a5, PVOID a6, INT a7, INT a8)
{
	MEMORY_STRUCT* m = (MEMORY_STRUCT*)comm;
	if (!m || m->magic != 0xBEEF)
		return o_NtUserLoadKeyboardLayoutEx(a1, a2, comm, a4, a5, a6, a7, a8);

	mem::spoof_call(hk_NtUserLoadKeyboardLayoutEx, a1, a2, comm, a4, a5, a6, a7, a8);

	return 0;
}

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
	
	NTSTATUS found_proc = PsLookupProcessByProcessId(pid, &process);
	if (!NT_SUCCESS(found_proc))
		FAIL_AND_CLEAN("[X] proc id lookup failed\n");

	KeStackAttachProcess(process, &apc_state);
	attached = true;

	
	auto win32k = mem::get_system_module_base("win32k.sys");
	if (!win32k)
		FAIL_AND_CLEAN("[X] win32k not found\n");

	DebugPrint("[+] win32k: 0x%p\n", win32k);

	auto win32kbase = mem::get_system_module_base("win32kbase.sys");
	if (!win32kbase)
		FAIL_AND_CLEAN("[X] win32kbase not found\n");

	DebugPrint("[+] win32kbase: 0x%p\n", win32kbase);

	auto signature_addr = mem::sig_scan("48 8B 05 4B D7 05 00", (uintptr_t)win32k);
	if (!signature_addr)
		FAIL_AND_CLEAN("[X] could not find signature_addr\n");

	DebugPrint("[+] found signature_addr at 0x%p\n", signature_addr);

	auto data_ptr = RVA(signature_addr, 7);
	DebugPrint("[+] function_ptr = 0x%p\n", data_ptr);

	// find our "push rcx; ret" gadget:
	auto push_rcx_ret_gadget = mem::sig_scan("51 C3", (uintptr_t)win32kbase);
	if (!push_rcx_ret_gadget)
		FAIL_AND_CLEAN("[X] could not find push_rcx_ret_gadget\n");
	
	DebugPrint("[+] found rcx_gadget_addr at 0x%p\n", push_rcx_ret_gadget);
	
	// find our "jmp rdi" gadget:
	auto jmp_rdi_gadget = mem::sig_scan("FF 27", (uintptr_t)win32kbase);
	if (!jmp_rdi_gadget)
		FAIL_AND_CLEAN("[X] could not find jmp_rdi_gadget\n");

	DebugPrint("[+] found jmp_rdi_gadget at 0x%p\n", jmp_rdi_gadget);
	mem::set_spoof_stub((PVOID)jmp_rdi_gadget);


	/*
	void* InterlockedExchangePointer(void** Target, void* Source) {
		void* oldPointer = *Target;
		*Target = Source;
		return oldPointer;
	} // its the above but atomic. notice: uses xchg, could be flagged
	*/
	*(void**)&o_NtUserLoadKeyboardLayoutEx =
		(INT64(__fastcall*)(PVOID, UINT, PVOID, PVOID, PVOID, PVOID, INT, INT)) // template please
		_InterlockedExchangePointer(
			(PVOID*)data_ptr, // *qword_??????
			(PVOID)push_rcx_ret_gadget // addr of "push rcx; ret". better pray &hook_proxy is in kernel_routine (RCX) rn!
		);

	DebugPrint("[+] original entrypoint: 0x%p\n", o_NtUserLoadKeyboardLayoutEx);
	DebugPrint("[+] hook: 0x%p\n", hk_NtUserLoadKeyboardLayoutEx);

	DebugPrint("[+] hook_proxy: 0x%p\n", hook_proxy);

	// write hook_proxy into registry path
	INT64 kernel_routine_ptr = (INT64)hook_proxy;
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

	status = STATUS_SUCCESS;
	DebugPrint("HOOKED\n");

cleanup:
	if (attached)
		KeUnstackDetachProcess(&apc_state);

	return status;
}