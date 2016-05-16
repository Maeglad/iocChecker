#pragma once

#ifndef FILEMODULE_H
#define FILEMODULE_H

#include <string>
#include <vector>
#include "Defines.h"
#include "HashModule.h"


#define FILE_EXACT_DATA 0
#define FILE_REGEX_DATA 1
#define FILE_HASH_MD5_DATA 2
#define FILE_HASH_SHA256_DATA 3
#define FILE_HASH_SHA1_DATA 4

typedef struct _file_search_data {
	int iocId;
	int dataId;

	std::wstring path;
	std::wstring name;
	std::wstring hash;
	int hashType;

	bool found;
} FILE_SEARCH_DATA;

class FileModule {
public:
	FileModule();
	~FileModule();

	int checkForFiles(std::vector<FILE_SEARCH_DATA> searchData, std::vector<FindData>* found);

private:
	int searchFiles(std::vector<FILE_SEARCH_DATA> searchData, std::wstring currpath, std::vector<FindData>* found);
	void enumerateDrives(std::vector<std::wstring>* volumes);
	HashModule* hashModule;
};

#endif /* FILECHECKER_H */

