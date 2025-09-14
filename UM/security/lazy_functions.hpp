#pragma once
#include <Windows.h>
#include "lazy_importer.hpp"

namespace Lazy {

    // USER32.DLL
    inline HWND LI_FindWindowA(const char* lpClassName, const char* lpWindowName) {
        return LI_FN(FindWindowA)(lpClassName, lpWindowName);
    }

    inline auto LI_GetAsyncKeyState = LI_FN(GetAsyncKeyState);
    inline auto LI_GetClientRect = LI_FN(GetClientRect);
    inline auto LI_GetSystemMetrics = LI_FN(GetSystemMetrics);
    inline auto LI_GetWindowLongA = LI_FN(GetWindowLongA);
    inline auto LI_GetWindowRect = LI_FN(GetWindowRect);
    inline auto LI_SetLayeredWindowAttributes = LI_FN(SetLayeredWindowAttributes);
    inline auto LI_SetWindowLongPtrA = LI_FN(SetWindowLongPtrA);
    inline auto LI_SetWindowPos = LI_FN(SetWindowPos);
    inline auto LI_ShowWindow = LI_FN(ShowWindow);

    // KERNEL32.DLL
    inline auto LI_GetCurrentProcess = LI_FN(GetCurrentProcess);
    inline auto LI_GetCurrentProcessId = LI_FN(GetCurrentProcessId);
    inline auto LI_GetCurrentThreadId = LI_FN(GetCurrentThreadId);
    inline auto LI_GetModuleHandleA = LI_FN(GetModuleHandleA);
    inline auto LI_GetModuleHandleW = LI_FN(GetModuleHandleW);
    inline auto LI_GetProcAddress = LI_FN(GetProcAddress);
    inline auto LI_GetSystemTimeAsFileTime = LI_FN(GetSystemTimeAsFileTime);
    inline auto LI_InitializeSListHead = LI_FN(InitializeSListHead);
    inline auto LI_IsDebuggerPresent = LI_FN(IsDebuggerPresent);
    inline auto LI_IsProcessorFeaturePresent = LI_FN(IsProcessorFeaturePresent);
    inline auto LI_LoadLibraryA = LI_FN(LoadLibraryA);
    inline auto LI_QueryPerformanceCounter = LI_FN(QueryPerformanceCounter);
    inline auto LI_RtlCaptureContext = LI_FN(RtlCaptureContext);
    inline auto LI_SetConsoleTitleA = LI_FN(SetConsoleTitleA);
    inline auto LI_SetUnhandledExceptionFilter = LI_FN(SetUnhandledExceptionFilter);
    inline auto LI_Sleep = LI_FN(Sleep);
    inline auto LI_TerminateProcess = LI_FN(TerminateProcess);
    inline auto LI_UnhandledExceptionFilter = LI_FN(UnhandledExceptionFilter);
}