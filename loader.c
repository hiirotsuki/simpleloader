/*
 * Copyright (c) 2024-2025 Ørjan Malde <red@foxi.me>
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

int InjectDll(HANDLE hProcess, const char *dllPath)
{
	HANDLE remoteThread;
	void *loadLibraryAddr;

	LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, lstrlen(dllPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if(!remoteMemory)
	{
		MessageBoxA(NULL, "Failed to allocate memory in target process.", NULL, 0x00000000L);
		return 0;
	}

	if(!WriteProcessMemory(hProcess, remoteMemory, dllPath, lstrlen(dllPath) + 1, NULL))
	{
		MessageBoxA(NULL, "Failed to write to target process memory.", NULL, 0x00000000L);
		VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
		return 0;
	}

	loadLibraryAddr = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	remoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, remoteMemory, 0, NULL);
	if(!remoteThread)
	{
		MessageBoxA(NULL, "Failed to create remote thread.", NULL, 0x00000000L);
		VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
		return 0;
	}

	WaitForSingleObject(remoteThread, INFINITE);

	VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
	CloseHandle(remoteThread);

	return 1;
}

int WinMainCRTStartup(void)
{
	int s1 = 0, s2 = 0;
	char dllBuf[64] = {0};
	char exeBuf[64] = {0};
	char dllPath[MAX_PATH];
	char iniPath[MAX_PATH];
	PROCESS_INFORMATION pi;
	STARTUPINFOA si;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	ZeroMemory(&pi, sizeof(pi));

	GetFullPathName("loader.ini", sizeof(iniPath), iniPath, NULL);
	s1 = GetPrivateProfileString("loader", "DLL", NULL, dllBuf, sizeof(dllBuf), iniPath);
	s2 = GetPrivateProfileString("loader", "EXE", NULL, exeBuf, sizeof(exeBuf), iniPath);

	GetFullPathName(dllBuf, sizeof(dllPath), dllPath, NULL);

	/* invalid value checks */
	if(s1 < 5 || s2 < 5)
	{
		MessageBoxA(NULL, "loader.ini does not exist or contains gibberish.", NULL, 0x00000000L);
		return 1;
	}

	if(!CreateProcessA(exeBuf, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		MessageBoxA(NULL, "Failed to create process.", NULL, 0x00000000L);
		return 1;
	}

	if(!InjectDll(pi.hProcess, dllPath))
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
