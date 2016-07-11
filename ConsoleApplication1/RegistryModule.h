#pragma once

#ifndef REGISTRYMODULE_H
#define REGISTRYMODULE_H

#include <windows.h>
#include <string>
#include <vector>
#include "Defines.h"

#define KEY_WOW64_64KEY (0x0100)
#define KEY_WOW64_32KEY (0x0200)
#define KEY_MAX_LENGTH 255
#define KEY_MAX_VALUE_LENGTH 16383

#define REGISTRY_EXACT_DATA 1
#define REGISTRY_NAME_DATA 2
#define REGISTRY_REGEX_DATA 3

typedef struct _REGISTRY_SEARCH_DATA {
	int iocId;
	int dataId;
	std::wstring path;
	std::wstring name; // ak je exact true obsahuje path napr. HKEY_CURRENT_USER\\subkey1\\subsubkey2\\ ...\\desiredkey
					   // inak obsahuje nazov key -> keyname
	std::wstring valueName; // nazov hodnoty, ak je noValue = true ignoruje sa

	std::wstring valueValue; // hodnota hodnoty, ak je noValue = true ignoruje sa 
	int dataLength;
	bool noValue;
	bool found;
} REGISTRY_SEARCH_DATA;
#ifndef HKEY_CLASSES_ROOT
#define HKEY_CLASSES_ROOT				((HKEY) 0x80000000)
#endif
#ifndef HKEY_CURRENT_USER
#define HKEY_CURRENT_USER				((HKEY) 0x80000001)
#endif
#ifndef HKEY_LOCAL_MACHINE
#define HKEY_LOCAL_MACHINE				((HKEY) 0x80000002)
#endif
#ifndef HKEY_USERS
#define HKEY_USERS					((HKEY) 0x80000003)
#endif
#ifndef HKEY_PERFORMANCE_DATA
#define HKEY_PERFORMANCE_DATA				((HKEY) 0x80000004)
#endif
#ifndef HKEY_PERFORMANCE_TEXT
#define HKEY_PERFORMANCE_TEXT				((HKEY) 0x80000050)
#endif
#ifndef HKEY_PERFORMANCE_NLSTEXT
#define HKEY_PERFORMANCE_NLSTEXT			((HKEY) 0x80000060)
#endif
#ifndef HKEY_CURRENT_CONFIG
#define HKEY_CURRENT_CONFIG				((HKEY) 0x80000005)
#endif
#ifndef HKEY_DYN_DATA
#define HKEY_DYN_DATA					((HKEY) 0x80000006)
#endif
#ifndef HKEY_CURRENT_USER_LOCAL_SETTINGS
#define HKEY_CURRENT_USER_LOCAL_SETTINGS		((HKEY) 0x80000007)
#endif

class RegistryModule {
public:
	void checkRegistry(std::vector<REGISTRY_SEARCH_DATA> searchData, std::vector<FindData>* found, std::vector<FailInfo>* fails);
private:
	bool checkValue(HKEY hKey, REGISTRY_SEARCH_DATA data, bool regexp, std::wstring* valName);
	bool FindKeyByNameOrValue(std::vector<REGISTRY_SEARCH_DATA> searchData, HKEY baseKey, std::wstring baseKeyName, std::wstring name, std::wstring path, std::vector<FindData>* found, std::vector<FailInfo>* fails);
	// bool compareData(std::wstring s, int searchLength, unsigned char* data, int dataSize, DWORD valueType);
	bool compareData(std::wstring s, unsigned char* data, int dataSize, DWORD valueType, bool regexp);
	BOOL SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege);
	int DropPrivileges();
	int GetPrivileges();
};

#endif /* REGISTRYMODULE_H */

