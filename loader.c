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
#include <winternl.h>

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)
(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
);

typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)
(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *pNtFreeVirtualMemory)
(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

pNtAllocateVirtualMemory NtAllocateVirtualMemory = NULL;
pNtWriteVirtualMemory NtWriteVirtualMemory = NULL;
pNtFreeVirtualMemory NtFreeVirtualMemory = NULL;

void CopyPointer(void *dest, void *src, size_t size)
{
	size_t i;
	unsigned char *d = (unsigned char *)dest;
	unsigned char *s = (unsigned char *)src;

	for(i = 0; i < size; i++)
		d[i] = s[i];
}

LPVOID NtAllocateMemory(HANDLE hProcess, SIZE_T size)
{
	NTSTATUS status;
	PVOID baseAddress = NULL;
	SIZE_T regionSize = size;

	status = NtAllocateVirtualMemory(hProcess, &baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if(status == 0)
		return baseAddress;

	return NULL;
}

BOOL NtWriteMemory(HANDLE hProcess, LPVOID address, LPCVOID buffer, SIZE_T size)
{
	SIZE_T bytesWritten = 0;
	NTSTATUS status = NtWriteVirtualMemory(hProcess, address, (PVOID)buffer, size, &bytesWritten);

	return (status == 0 && bytesWritten == size);
}

BOOL NtFreeMemory(HANDLE hProcess, LPVOID address)
{
	NTSTATUS status;
	PVOID baseAddress = address;
	SIZE_T regionSize = 0;

	status = NtFreeVirtualMemory(hProcess, &baseAddress, &regionSize, MEM_RELEASE);

	return (status == 0);
}

int InjectDll(HANDLE hProcess, const char *dllPath)
{
	HANDLE remoteThread;
	LPVOID remoteMemory;
	size_t dllPathLen;
	LPTHREAD_START_ROUTINE pLoadLibraryA = NULL;
	FARPROC pProc;

	dllPathLen = lstrlen(dllPath) + 1;
	remoteMemory = NtAllocateMemory(hProcess, dllPathLen);
	if (!remoteMemory)
	{
		MessageBoxA(NULL, "Failed to allocate memory in target process.", "Memory Allocation Failed", MB_OK);
		return 0;
	}

	if (!NtWriteMemory(hProcess, remoteMemory, dllPath, dllPathLen))
	{
		MessageBoxA(NULL, "Failed to write to target process memory.", "Write Error", MB_OK);
		NtFreeMemory(hProcess, remoteMemory);
		return 0;
	}

	pProc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	CopyPointer(&pLoadLibraryA, &pProc, sizeof(pProc));
	remoteThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibraryA, remoteMemory, 0, NULL);
	if(!remoteThread)
	{
		MessageBoxA(NULL, "Failed to create remote thread.", "Thread Creation Error", MB_OK);
		NtFreeMemory(hProcess, remoteMemory);
		return 0;
	}

	WaitForSingleObject(remoteThread, INFINITE);

	NtFreeMemory(hProcess, remoteMemory);
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
	HMODULE hNtdll;
	FARPROC pProc;
	PROCESS_INFORMATION pi;
	STARTUPINFOA si;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	ZeroMemory(&pi, sizeof(pi));

	hNtdll = GetModuleHandleA("ntdll.dll");

	pProc = GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	CopyPointer(&NtAllocateVirtualMemory, &pProc, sizeof(pProc));

	pProc = GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	CopyPointer(&NtWriteVirtualMemory, &pProc, sizeof(pProc));

	pProc = GetProcAddress(hNtdll, "NtFreeVirtualMemory");
	CopyPointer(&NtFreeVirtualMemory, &pProc, sizeof(pProc));

	GetFullPathName("loader.ini", sizeof(iniPath), iniPath, NULL);
	s1 = GetPrivateProfileString("loader", "DLL", NULL, dllBuf, sizeof(dllBuf), iniPath);
	s2 = GetPrivateProfileString("loader", "EXE", NULL, exeBuf, sizeof(exeBuf), iniPath);

	GetFullPathName(dllBuf, sizeof(dllPath), dllPath, NULL);

	/* invalid value checks */
	if(s1 < 5 || s2 < 5)
	{
		MessageBoxA(NULL, "loader.ini does not exist or contains invalid entries.", "Configuration Error", MB_OK);
		return 1;
	}

	if(!CreateProcessA(exeBuf, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		char errorMsg[256];
		wsprintfA(errorMsg, "Failed to create process. Error: %lu", GetLastError());
		MessageBoxA(NULL, errorMsg, "Process Creation Error", MB_OK);
		return 1;
	}

	if(!InjectDll(pi.hProcess, dllPath))
	{
		MessageBoxA(NULL, "Failed to inject DLL.", "Injection Failed", MB_OK);
		TerminateProcess(pi.hProcess, 1);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 1;
	}

	if(ResumeThread(pi.hThread) == (DWORD)-1)
	{
		MessageBoxA(NULL, "Failed to resume process.", "Resume Error", MB_OK);
		TerminateProcess(pi.hProcess, 1);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 1;
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return 0;
}
