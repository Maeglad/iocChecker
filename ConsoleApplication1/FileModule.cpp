#ifndef UNICODE
#define UNICODE
#endif

#include "stdafx.h"

#include "FileModule.h"

#ifndef DEBUG
#define DEBUG 0
#endif

#include "HashModule.h"
#include "Ioc-parser.h"
#include "Defines.h"

#include <windows.h>

#include <iostream>

#include <string>
#include <sstream>

#include <vector>
#include <regex>

FileModule::FileModule() {
	this->hashModule = new HashModule();
}
FileModule::~FileModule() {
	delete hashModule;
}

int FileModule::checkForFiles(std::vector<FILE_SEARCH_DATA> searchData, std::vector<FindData>* found) {
	std::vector<std::wstring> volumes;
	volumes.clear();
	enumerateDrives(&volumes);

	for (int i = 0; i < searchData.size(); ++i) {
		if ((searchData[i].dataId == FILE_EXACT_DATA) && (searchData[i].path.compare(L"") != 0) && (searchData[i].name.compare(L"") != 0)) {
			std::wstring path;
			path = searchData[i].path;
			path.append(L"\\");
			path.append(searchData[i].name);
			if (FILE* f = _wfopen(path.c_str(), L"rb")) {
				if (searchData[i].hash.compare(L"") == 0) {
					FindData fd;
					fd.id = i;
					fd.data.push_back(path);
					found->push_back(fd);
					std::wstring ws(L"");
					fd.data.push_back(ws);
					searchData[i].found == true;
				}
				else {
					std::wstring hash;
					if (searchData[i].hashType == FILE_HASH_MD5_DATA) {

						hashModule->calc_md5W(path, &hash);
					}
					if (searchData[i].hashType == FILE_HASH_SHA256_DATA) {

						hashModule->calc_sha256W(path, &hash);
					}
					if (searchData[i].hashType == FILE_HASH_SHA1_DATA) {

						hashModule->calc_sha1W(path, &hash);
					}
					if (searchData[i].hash.compare(hash) == 0) {
						searchData[i].found = true;
						FindData fd;
						fd.id = i;
						fd.data.push_back(path);
						fd.data.push_back(hash);
						found->push_back(fd);
					}
				}
				fclose(f);
			}

		}
	}
	
	bool stop = true;
	for (int i = 0; i < searchData.size(); ++i) {
		if (searchData[i].found == false) stop = false;
	}
	
	if (stop)return 0;

	for (int i = 0; i < volumes.size(); ++i) {
		volumes[i].pop_back();
		//std::wcout << volumes[i] << std::endl;
	}

	for (int i = 0; i < volumes.size(); ++i) {
		searchFiles(searchData, volumes[i], found);
	}
	return 0;
}


int FileModule::searchFiles(std::vector<FILE_SEARCH_DATA> searchData, std::wstring currpath, std::vector<FindData>* found) {

	WIN32_FIND_DATAW findFileData;
	HANDLE hFind;
	std::wstring path = currpath + L"\\*";
	//sstd::wcout << currpath << std::endl;
	hFind = FindFirstFileW(path.c_str(), &findFileData);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		return 1;
		
	}
	do {

		// check searchfiles a regexes

		for (int i = 0; i < searchData.size(); ++i) {
			if (searchData[i].found)continue;
			// check path
			if (searchData[i].dataId == FILE_EXACT_DATA) {
				if ((searchData[i].path.compare(currpath) == 0) ||
					(searchData[i].path.compare(L"") == 0)) {
					// check name
					if ((searchData[i].name.compare(findFileData.cFileName) == 0) ||
						(searchData[i].name.compare(L"") == 0)) {
						//check hash
						if (searchData[i].hash.compare(L"") == 0) {
							FindData fd;
							fd.id = i;
							std::wstring ws = currpath;
							//std::wcout << currpath << std::endl;
							ws.append(L"\\");
							ws.append(searchData[i].name);
							fd.data.push_back(ws);
							

							//std::wstring wout;
							
							//hashModule->calc_sha256W(ws, &wout);
							//std::wcout << wout << std::endl;
							ws = L"";
							fd.data.push_back(ws);
							found->push_back(fd);
						}
						else {
							std::wstring hash;
							std::wstring path;
							path = currpath;
							path.append(L"\\");
							path.append(findFileData.cFileName);
							if (searchData[i].hashType == FILE_HASH_MD5_DATA) {
								hashModule->calc_md5W(path, &hash);
							}

							if (searchData[i].hashType == FILE_HASH_SHA1_DATA) {
								hashModule->calc_sha1W(path, &hash);
							}

							if (searchData[i].hashType == FILE_HASH_SHA256_DATA) {
								hashModule->calc_sha256W(path, &hash);
							}
							
							if (searchData[i].hash.compare(hash) == 0) {
								searchData[i].found = true;
								FindData fd;
								fd.id = i;
								fd.data.push_back(path);
								fd.data.push_back(hash);
								found->push_back(fd);
							}
						}
					}
				}
			}

			if (searchData[i].dataId == FILE_REGEX_DATA) {
				std::wregex regPath, regName;
				regPath.assign(searchData[i].path);

				std::wstring comparePath;
				comparePath.append(currpath);
				comparePath.append(L"\\");
				comparePath.append(findFileData.cFileName);
				if ((std::regex_match(comparePath.c_str(), regPath)) ||
					(searchData[i].path.compare(L"") == 0) ||
					(std::regex_match(findFileData.cFileName, regPath))
					) {
					//check hash
					if (searchData[i].hash.compare(L"") == 0) {

						FindData fd;
						fd.id = i;
						std::wstring ws = currpath;
						ws.append(L"\\");
						ws.append(findFileData.cFileName);
						fd.data.push_back(ws);
						ws = L"";

						fd.data.push_back(ws);
						found->push_back(fd);
					}
					else {
						std::wstring hash;
						std::wstring path;
						path = currpath;
						path.append(L"\\");
						path.append(findFileData.cFileName);
						if (searchData[i].hashType == FILE_HASH_MD5_DATA) {
							hashModule->calc_md5W(path, &hash);
						}

						if (searchData[i].hashType == FILE_HASH_SHA1_DATA) {
							hashModule->calc_sha1W(path, &hash);
						}

						if (searchData[i].hashType == FILE_HASH_SHA256_DATA) {
							hashModule->calc_sha256W(path, &hash);
						}
						//std::wcout << path << std::endl;
						//std::wcout << hash << std::endl << searchData[i].hash << std::endl;
						if (searchData[i].hash.compare(hash) == 0) {
							FindData fd;
							fd.id = i;
							fd.data.push_back(path);
							fd.data.push_back(hash);
							found->push_back(fd);
						}
					}

				}
			}
		}

		if ((findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
			(wcscmp(L"..", findFileData.cFileName) != 0) &&
			(wcscmp(L".", findFileData.cFileName) != 0))
		{
			searchFiles(searchData, currpath + L"\\" + findFileData.cFileName, found);
		}



	} while (FindNextFileW(hFind, &findFileData) != 0);
}

void FileModule::enumerateDrives(std::vector<std::wstring>* volumes) {
	DWORD value, size;

	size = GetLogicalDriveStringsW(0, NULL);
	LPTSTR buffer = new WCHAR[size];

	// vracia null(\0) za kazdym disk driveom
	value = GetLogicalDriveStringsW(size, buffer);

	for (int i = 0; i < size - 2; ++i) {
		if (buffer[i] == '\0') {
			buffer[i] = ' ';
		}
	}

	std::wstringstream ss(buffer);
	std::wstring item;

	while (!ss.eof()) {
		std::getline(ss, item, L' ');
		volumes->push_back(item);
	};


	delete buffer;
}