#include "mem.hpp"
#include "imports.hpp"
#include <cstdint>

INT64(__fastcall* Qword_ptrOriginal)(PVOID, PVOID, PVOID, PVOID, PVOID);

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

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(registry_path);

	//Hook the function to NtSetCompositionSurfaceAnalogExclusive
	mem::Hook(&NtSetCompositionSurfaceAnalogExclusive);

	DebugPrint("HOOKED\n");
	return STATUS_SUCCESS;
}