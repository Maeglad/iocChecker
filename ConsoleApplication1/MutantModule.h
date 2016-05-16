#pragma once

/*
* To change this license header, choose License Headers in Project Properties.
* To change this template file, choose Tools | Templates
* and open the template in the editor.
*/

/*
* File:   MutantModule.h
* Author: User
*
* Created on April 9, 2016, 11:42 AM
*/

#ifndef MUTANTMODULE_H
#define MUTANTMODULE_H

#include <vector>
#include <string>
#include <windows.h>
#include "Defines.h"






typedef enum _SYSTEM_HANDLE_FLAGS
{
	PROTECT_FROM_CLOSE = 1,
	INHERIT = 2
} SYSTEM_HANDLE_FLAGS;

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION // Size=20
{
	ULONG NumberOfHandles; // Size=4 Offset=0
	SYSTEM_HANDLE Handles[1]; // Size=16 Offset=4
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFROMATION;


typedef enum OBJECT_INFORMATION_CLASS {// z msdn nepouzivam len pre hodnoty potom zmaz
	objectBasicInformation = 0,
	objectNameInformation = 1,
	objectTypeInformation = 2
};

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;


#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define SystemProcessInformation 5
#define SystemHandleInformation 16
#define NT_SUCCESS(x) ((x) >= 0)
#define NTSTATUS LONG

typedef struct _MUTEX_SEARCH_DATA {
	int iocId;
	std::wstring data;
	bool found;
} MUTEX_SEARCH_DATA;

class MutantModule {
public:
	void checkMutexes(std::vector<MUTEX_SEARCH_DATA> searchData, std::vector<FindData>* found);
private:
	BOOL SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege);
	int GetPrivileges();
	int DropPrivileges();
};

#endif /* MUTANTMODULE_H */

