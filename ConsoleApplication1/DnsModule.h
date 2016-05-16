#pragma once

#ifndef DNSMODULE_H
#define DNSMODULE_H

#include <windows.h>
#include <windns.h>
#include <string>
#include <vector>
#include "Defines.h"

typedef struct _DNS_CACHE_ENTRY {
	struct _DNS_CACHE_ENTRY* pNext; // Pointer to next entry
	PWSTR pName; // DNS Record Name
	WORD wType; // DNS Record Type
	WORD wDataLength; // Not referenced
	unsigned long flags;
	// este tu pokracuju nejake data ale tie nepotrebujem
} DNSRECORD, *PDNSRECORD;

typedef struct _DNS_SEARCH_DATA {
	int iocId;
	std::wstring data;
	bool found;
} DNS_SEARCH_DATA;

class DnsModule {
public:
	void checkDnsEntries(std::vector<DNS_SEARCH_DATA> names, std::vector<FindData>* found);
private:
	typedef int(WINAPI *DNS_GET_CACHE_DATA_TABLE)(PDNS_RECORD*);
	typedef void (WINAPI *P_DnsApiFree)(PVOID pData);

};

#endif /* DNSMODULE_H */

