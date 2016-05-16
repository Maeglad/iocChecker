#pragma once

#ifndef PROCESSMODULE_H
#define PROCESSMODULE_H

#define _WIN32_WINNT 0x0501
#define PSAPI_VERSION 1

#include <windows.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <sstream>
#include <regex>
#include "Defines.h"





#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define SystemProcessInformation 5
#define SystemHandleInformation 16
#define NT_SUCCESS(x) ((x) >= 0)
#define NTSTATUS LONG

typedef struct _SYSTEM_PROCESS_INFORMATION // Size=184
{
	ULONG NextEntryOffset; // Size=4 Offset=0
	ULONG NumberOfThreads; // Size=4 Offset=4
	LARGE_INTEGER WorkingSetPrivateSize; // Size=8 Offset=8
	ULONG HardFaultCount; // Size=4 Offset=16
	ULONG NumberOfThreadsHighWatermark; // Size=4 Offset=20
	ULONGLONG CycleTime; // Size=8 Offset=24
	LARGE_INTEGER CreateTime; // Size=8 Offset=32
	LARGE_INTEGER UserTime; // Size=8 Offset=40
	LARGE_INTEGER KernelTime; // Size=8 Offset=48
	UNICODE_STRING ImageName; // Size=8 Offset=56
	LONG BasePriority; // Size=4 Offset=64
	PVOID UniqueProcessId; // Size=4 Offset=68
	PVOID InheritedFromUniqueProcessId; // Size=4 Offset=72
	ULONG HandleCount; // Size=4 Offset=76
	ULONG SessionId; // Size=4 Offset=80
	ULONG UniqueProcessKey; // Size=4 Offset=84
	ULONG PeakVirtualSize; // Size=4 Offset=88 
						   // podla vsetkeho je tato cast nizsie sice pre mna nepotrebna ale je rozn pre 32 a 64 bit arch
	ULONG VirtualSize; // Size=4 Offset=92
	ULONG PageFaultCount; // Size=4 Offset=96
	ULONG PeakWorkingSetSize; // Size=4 Offset=100
	ULONG WorkingSetSize; // Size=4 Offset=104
	ULONG QuotaPeakPagedPoolUsage; // Size=4 Offset=108
	ULONG QuotaPagedPoolUsage; // Size=4 Offset=112
	ULONG QuotaPeakNonPagedPoolUsage; // Size=4 Offset=116
	ULONG QuotaNonPagedPoolUsage; // Size=4 Offset=120
	ULONG PagefileUsage; // Size=4 Offset=124
	ULONG PeakPagefileUsage; // Size=4 Offset=128
	ULONG PrivatePageCount; // Size=4 Offset=132
	LARGE_INTEGER ReadOperationCount; // Size=8 Offset=136
	LARGE_INTEGER WriteOperationCount; // Size=8 Offset=144
	LARGE_INTEGER OtherOperationCount; // Size=8 Offset=152
	LARGE_INTEGER ReadTransferCount; // Size=8 Offset=160
	LARGE_INTEGER WriteTransferCount; // Size=8 Offset=168
	LARGE_INTEGER OtherTransferCount; // Size=8 Offset=176
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;



#define PROCESS_NAME_DATA 0
#define PROCESS_REGEX_DATA 1
#define PROCESS_HASH_SHA256_DATA 2
#define PROCESS_HASH_MD5_DATA 3
#define PROCESS_HASH_SHA1_DATA 4

#define ERROR_PROCADDRESS 1
#define ERROR_ALLOCATION 2
#define ERROR_FUNCTION 3
#define ERROR_OK 0

typedef struct _PROCESS_SEARCH_DATA {
	int iocId;
	int dataId;

	std::wstring data;
	bool found;

} PROCESS_SEARCH_DATA, *PPROCESS_SEARCH_DATA;

class ProcessModule {
public:
	int checkProcesses(std::vector<PROCESS_SEARCH_DATA> searchData, std::vector<FindData>* found);

private:
	void enumerateDrives(std::vector<std::wstring>* volumes);
	BOOL SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege);
	int GetPrivileges();
	int DropPrivileges();
	std::wstring getProcessPath(DWORD pid);



};
#endif /* PROCESSMODULE_H */

