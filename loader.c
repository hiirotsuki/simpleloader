/*
 * Copyright (c) 2024 Ørjan Malde <red@foxi.me>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <windows.h>

int inject_dll(HANDLE hProcess, const char* dll_path)
{
	HANDLE remote_thread;
	void *load_library_addr;

	LPVOID remote_memory = VirtualAllocEx(hProcess, NULL, lstrlen(dll_path) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if(!remote_memory)
	{
		MessageBoxA(NULL, "Failed to allocate memory in target process.", NULL, 0x00000000L);
		return 0;
	}

	if(!WriteProcessMemory(hProcess, remote_memory, dll_path, lstrlen(dll_path) + 1, NULL))
	{
		MessageBoxA(NULL, "Failed to write to target process memory.", NULL, 0x00000000L);
		VirtualFreeEx(hProcess, remote_memory, 0, MEM_RELEASE);
		return 0;
	}

	load_library_addr = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	remote_thread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)load_library_addr, remote_memory, 0, NULL);
	if(!remote_thread)
	{
		MessageBoxA(NULL, "Failed to create remote thread.", NULL, 0x00000000L);
		VirtualFreeEx(hProcess, remote_memory, 0, MEM_RELEASE);
		return 0;
	}

	WaitForSingleObject(remote_thread, INFINITE);

	VirtualFreeEx(hProcess, remote_memory, 0, MEM_RELEASE);
	CloseHandle(remote_thread);

	return 1;
}

int WinMainCRTStartup(void)
{
	int s1 = 0, s2 = 0;
	char dll_buf[64] = {0};
	char exe_buf[64] = {0};
	char dll_path[MAX_PATH];
	char ini_path[MAX_PATH];
	PROCESS_INFORMATION pi;
	STARTUPINFOA si;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	ZeroMemory(&pi, sizeof(pi));

	GetFullPathName("loader.ini", sizeof(ini_path), ini_path, NULL);
	s1 = GetPrivateProfileString("loader", "DLL", NULL, dll_buf, sizeof(dll_buf), ini_path);
	s2 = GetPrivateProfileString("loader", "EXE", NULL, exe_buf, sizeof(exe_buf), ini_path);

	GetFullPathName(dll_buf, sizeof(dll_path), dll_path, NULL);

	/* invalid value checks */
	if(s1 < 5 || s2 < 5)
	{
		MessageBoxA(NULL, "loader.ini does not exist or contains gibberish.", NULL, 0x00000000L);
		return 1;
	}

	if(!CreateProcessA(exe_buf, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		MessageBoxA(NULL, "Failed to create process.", NULL, 0x00000000L);
		return 1;
	}

	if(!inject_dll(pi.hProcess, dll_path))
	{
		MessageBoxA(NULL, "Failed to inject DLL.", NULL, 0x00000000L);
		TerminateProcess(pi.hProcess, 1);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 1;
	}

	if(ResumeThread(pi.hThread) == (DWORD)-1)
	{
		MessageBoxA(NULL, "Failed to resume process.", NULL, 0x00000000L);
		TerminateProcess(pi.hProcess, 1);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 1;
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return 0;
}
