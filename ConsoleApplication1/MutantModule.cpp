#ifndef UNICODE
#define UNICODE
#endif

#include "stdafx.h"
#include "MutantModule.h"
#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <regex>
typedef NTSTATUS 
(NTAPI *typeNtQuerySystemInformation) (
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI *typeNtQueryObject)(
	HANDLE handle,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI *typeNtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);


void MutantModule::checkMutexes(std::vector<MUTEX_SEARCH_DATA> searchData, std::vector<FindData>* found) {

	typeNtQuerySystemInformation fpNTQSI = (typeNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	typeNtQueryObject fpNTQO = (typeNtQueryObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");
	typeNtDuplicateObject fpNTDO = (typeNtDuplicateObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject");

	GetPrivileges();

	ULONG bufferLength = 1000;
	PVOID handleInfo;
	NTSTATUS status;
	DWORD returnLength = 1000;
	handleInfo = (PSYSTEM_HANDLE_INFROMATION)VirtualAlloc(NULL, bufferLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	while ((status = fpNTQSI(SystemHandleInformation, handleInfo, bufferLength, &returnLength)) == STATUS_INFO_LENGTH_MISMATCH) {
		VirtualFree(handleInfo, 0, MEM_FREE);
		bufferLength *= 2;
		handleInfo = VirtualAlloc(NULL, bufferLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	}

	PSYSTEM_HANDLE_INFROMATION shi = (PSYSTEM_HANDLE_INFROMATION)handleInfo;

	int pom;

	for (int i = 0; i < shi->NumberOfHandles; ++i) {

		SYSTEM_HANDLE handle = shi->Handles[i];

		ULONG size;
		DWORD pid = handle.ProcessId;
		HANDLE hProcess = NULL;
		PVOID pvObjectNameInfo;

		hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
		if (hProcess == NULL) {

			continue;
		}

		HANDLE hDuplicate = NULL;

		if (!NT_SUCCESS(fpNTDO(hProcess, (void *)handle.Handle, GetCurrentProcess(), &hDuplicate, 0, 0, 0))) {

			CloseHandle(hProcess);
			continue;
		}



		POBJECT_TYPE_INFORMATION pObjectTypeInformation;
		ULONG returnLength;

		fpNTQO(hDuplicate, objectTypeInformation, NULL, 0, &returnLength);

		pObjectTypeInformation = (POBJECT_TYPE_INFORMATION)VirtualAlloc(NULL, returnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		LONG value;
		ULONG ret;

		if ((value = fpNTQO(hDuplicate, objectTypeInformation, pObjectTypeInformation, returnLength, &ret)) != 0) {

			std::wcout << "NtQueryObject failed: " << GetLastError() << std::endl;
			CloseHandle(hDuplicate);
			CloseHandle(hProcess);

			std::wcout << (ULONG)value << std::endl;
			continue;
		}

		std::wstring ws = pObjectTypeInformation->Name.Buffer;

		if (ws.compare(L"Mutant") != 0) {
			VirtualFree(pObjectTypeInformation, 0, MEM_RELEASE);
			CloseHandle(hDuplicate);
			CloseHandle(hProcess);
			continue;
		}

		fpNTQO(hDuplicate, objectNameInformation, NULL, 0, &returnLength);

		pvObjectNameInfo = VirtualAlloc(NULL, returnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!NT_SUCCESS(fpNTQO(hDuplicate, objectNameInformation, pvObjectNameInfo, returnLength, NULL))) {
			std::wcout << "Fetch name failed." << std::endl;
			CloseHandle(hDuplicate);
			CloseHandle(hProcess);
			VirtualFree(pvObjectNameInfo, 0, MEM_RELEASE);
		}

		UNICODE_STRING name = *(PUNICODE_STRING)pvObjectNameInfo;

		if (name.Length != 0) {
			std::wstring wss(name.Buffer);

			for (int i = 0; i < searchData.size(); ++i) {
				if (searchData[i].found)continue;
				if (wss.find(searchData[i].data.c_str()) != std::wstring::npos) {
					searchData[i].found = true;
					FindData fd;
					fd.id = i;
					fd.data.push_back(wss);
					found->push_back(fd);
				}
			}
		}

		VirtualFree(pvObjectNameInfo, 0, MEM_RELEASE);
		VirtualFree(pObjectTypeInformation, 0, MEM_RELEASE);
		CloseHandle(hDuplicate);
		CloseHandle(hProcess);


	}
	VirtualFree(handleInfo, 0, MEM_RELEASE);
	DropPrivileges();
}

int MutantModule::GetPrivileges() {
	HANDLE hToken;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		return 1;
	}

	if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
	{
		CloseHandle(hToken);
		return 1;
	}

	CloseHandle(hToken);
	return 0;
}

int MutantModule::DropPrivileges() {
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		return 1;
	}

	if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
	{
		CloseHandle(hToken);
		return 1;
	}
	CloseHandle(hToken);
	return 0;
}

BOOL MutantModule::SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege) {
	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	if (!LookupPrivilegeValue(NULL, Privilege, &luid)) return FALSE;

	// 
	// first pass.  get current privilege setting
	// 
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0;

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		&tpPrevious,
		&cbPrevious
	);

	if (GetLastError() != ERROR_SUCCESS) return FALSE;

	// 
	// second pass.  set privilege based on previous setting
	// 
	tpPrevious.PrivilegeCount = 1;
	tpPrevious.Privileges[0].Luid = luid;

	if (bEnablePrivilege) {
		tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
	}
	else {
		tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &
			tpPrevious.Privileges[0].Attributes);
	}

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tpPrevious,
		cbPrevious,
		NULL,
		NULL
	);

	if (GetLastError() != ERROR_SUCCESS) return FALSE;

	return TRUE;
}