#include "stdafx.h"
#include "ProcessModule.h"
#include "HashModule.h"
#include <iostream>
typedef NTSTATUS(NTAPI *typeNtQuerySystemInformation) (
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

void ProcessModule::enumerateDrives(std::vector<std::wstring>* volumes) {
	DWORD value, size;

	size = GetLogicalDriveStrings(0, NULL);
	LPWSTR buffer = new WCHAR[size];

	// vracia null(\0) za kazdym disk driveom
	value = GetLogicalDriveStringsW(size, buffer);

	for (int i = 0; i < size - 1; ++i) {
		if (buffer[i] == '\0') {
			buffer[i] = ' ';
		}
	}

	std::wstringstream ss(buffer);
	std::wstring item;



	while (!ss.eof()) {
		std::getline(ss, item, (wchar_t)' ');
		volumes->push_back(item);
	};
	delete buffer;
}

int ProcessModule::checkProcesses(std::vector<PROCESS_SEARCH_DATA> searchData, std::vector<FindData>* found) {
	PVOID buffer;
	ULONG returnLength = 0;

	PSYSTEM_PROCESS_INFORMATION spi;

	typeNtQuerySystemInformation fpNTQSI = NULL;
	fpNTQSI = (typeNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	if (fpNTQSI == NULL) {
		return ERROR_PROCADDRESS;
	}
	int ret = GetPrivileges();
	// get required size
	fpNTQSI(SystemProcessInformation, NULL, 0, &returnLength);
	buffer = VirtualAlloc(NULL, returnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!buffer) {
		return ERROR_ALLOCATION;
	}
	// get process table
	if (!NT_SUCCESS(fpNTQSI(SystemProcessInformation, buffer, returnLength, NULL))) {
		VirtualFree(buffer, 0, MEM_RELEASE);
		return ERROR_FUNCTION;
	}

	spi = (PSYSTEM_PROCESS_INFORMATION)buffer;

	std::vector<std::wstring> volumes;
	enumerateDrives(&volumes);

	
	if (ret == 1) {
		std::wcout << L"Cant get privileges" << std::endl;

	}
	while (spi->NextEntryOffset) {
		for (int i = 0; i < searchData.size(); ++i) {
			if (spi->ImageName.Buffer == NULL)continue;
			if (searchData[i].found) continue;
			if (searchData[i].dataId == PROCESS_NAME_DATA) {

				if (wcscmp(searchData[i].data.c_str(), spi->ImageName.Buffer) == 0) {
					FindData fd;
					fd.id = i;
					std::wstring w(spi->ImageName.Buffer);
					fd.data.push_back(w);
					w = getProcessPath(PtrToUlong(spi->UniqueProcessId));
					fd.data.push_back(w);
					found->push_back(fd);
					continue;
				}
			}
			if (searchData[i].dataId == PROCESS_REGEX_DATA) {
				std::wregex reg(searchData[i].data.c_str());
				if (std::regex_match(spi->ImageName.Buffer, reg)) {
					FindData fd;
					fd.id = i;
					std::wstring w(spi->ImageName.Buffer);
					fd.data.push_back(w);
					fd.data.push_back(getProcessPath(PtrToUlong(spi->UniqueProcessId)));
					found->push_back(fd);
					continue;
				}
			}
		
			if ((searchData[i].dataId == PROCESS_HASH_SHA256_DATA) ||
				(searchData[i].dataId == PROCESS_HASH_SHA1_DATA) ||
				(searchData[i].dataId == PROCESS_HASH_MD5_DATA)) {
				DWORD pid = PtrToUlong(spi->UniqueProcessId);
				
				HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
				LPWSTR ibuffer = new WCHAR[32767];
				LPWSTR longName = new WCHAR[32767];
				DWORD ret = GetProcessImageFileNameW(processHandle, ibuffer, 32767);
				
				if (ret == 0) {
					// ERROR
				}
				std::wstring kernelPath = ibuffer;
				LPWSTR dosDevice = new WCHAR[32767];
				std::wstring path;
				for (int i = 0; i < volumes.size(); ++i) {
					

					DWORD ret = QueryDosDeviceW(volumes[i].substr(0, volumes[i].size() - 1).c_str(), dosDevice, 32767);
					std::wstring device = dosDevice;
					if (kernelPath.find(device.c_str()) != std::string::npos) {
						path = volumes[i] + kernelPath.substr(device.length() + 1);
						break;
					}
				}

				ret = GetLongPathNameW(path.c_str(), longName, 32767);
				
				if (ret == 0) {
					// ERROR
					std::wcout << "Cannot get process filename: " << spi->ImageName.Buffer << std::endl;
				}
				else {
					
					

					HashModule hashModule;
					std::wstring hash;
					if (searchData[i].dataId == PROCESS_HASH_MD5_DATA) {
						hashModule.calc_md5W(longName, &hash);
					}
					if (searchData[i].dataId == PROCESS_HASH_SHA256_DATA) {
						hashModule.calc_sha256W(longName, &hash);
					}
					if (searchData[i].dataId == PROCESS_HASH_SHA1_DATA) {
						hashModule.calc_sha1W(longName, &hash);
					}
					
					if (wcscmp(hash.c_str(), searchData[i].data.c_str()) == 0) {
						FindData fd;
						fd.id = i;
						std::wstring w(spi->ImageName.Buffer);
						fd.data.push_back(w);
						fd.data.push_back(getProcessPath(PtrToUlong(spi->UniqueProcessId)));
						found->push_back(fd); 
						continue;
					}
				}
				delete ibuffer, longName;
				CloseHandle(processHandle);
			}
		}

		spi = (PSYSTEM_PROCESS_INFORMATION)(((LPBYTE)spi) + spi->NextEntryOffset);

	}
	DropPrivileges();

	VirtualFree(buffer, 0, MEM_RELEASE);
	return ERROR_OK;
}

std::wstring ProcessModule::getProcessPath(DWORD pid) {

	std::vector<std::wstring> volumes;
	enumerateDrives(&volumes);
	
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
	LPWSTR ibuffer = new WCHAR[32767];
	LPWSTR longName = new WCHAR[32767];
	DWORD ret = GetProcessImageFileNameW(processHandle, ibuffer, 32767);
	
	if (ret == 0) {
		// ERROR
	}
	std::wstring kernelPath = ibuffer;
	LPWSTR dosDevice = new WCHAR[32767];
	std::wstring path;
	for (int i = 0; i < volumes.size(); ++i) {
		
		DWORD ret = QueryDosDeviceW(volumes[i].substr(0, volumes[i].size() - 1).c_str(), dosDevice, 256);
		if (ret == 0) { std::wcout << L"Error QueryDosDevice in ProcessModule: " << GetLastError() << std::endl; }
		
		std::wstring device = dosDevice;
		if (kernelPath.find(device.c_str()) != std::string::npos) {
			path = volumes[i] + kernelPath.substr(device.length() + 1);
			break;
		}
	}
	ret = GetLongPathNameW(path.c_str(), longName, 32767);
	
	if (ret == 0) {
		std::wstring ws(L"");
		return ws;

	}
	
	std::wstring retStr(longName);
	return retStr;
}

int ProcessModule::GetPrivileges() {

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

int ProcessModule::DropPrivileges() {
	HANDLE hProcess;
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

BOOL ProcessModule::SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege) {
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