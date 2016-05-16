#pragma once

#ifndef DEFINES_H
#define DEFINES_H

#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <vector>
#include <string>

typedef struct {
	std::wstring type;
	std::wstring data;
}FailInfo;

typedef struct _UNICODE_STRING {
	USHORT         Length;
	USHORT         MaximumLength;
	PWSTR          Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct {
	int id;
	std::vector<std::wstring> data;
} FindData;

#endif /* DEFINES_H */

