#pragma once
#include <cstdio>
#include <memory>
#include <algorithm>
#include <array>
#include <cstdint>
#include <Windows.h>

#define okay(msg, ...) print_encrypted("[+] " msg, ##__VA_ARGS__)
#define info(msg, ...) print_encrypted("[i] " msg, ##__VA_ARGS__)
#define warn(msg, ...) print_encrypted("[-] " msg, ##__VA_ARGS__)
#define erro(msg, ...) print_encrypted("[X] " msg, ##__VA_ARGS__)

// do while loop protects macro {} inside short calls
#define print_encrypted(msg, ...) \
	do { \
		auto enc_msg = skCrypt(msg  "\n"); \
		printf(enc_msg.decrypt(), ##__VA_ARGS__); \
		enc_msg.clear(); \
	} while (0)

// functor!!!
struct HandleDisposer
{
	// unique_ptr will check for "pointer" type on deleter
	// we can now pass HANDLE to our unique_ptr
	using pointer = HANDLE;

	void operator()(HANDLE handle) const
	{
		// not all winapi funcs ret INVALID_HANDLE_VALUE
		if (handle && handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(handle);
		}
	}
};

// this way, handle is automatically closed when std::unique_ptr goes out of scope or is reset
using uniqueHandle = std::unique_ptr<HANDLE, HandleDisposer>;