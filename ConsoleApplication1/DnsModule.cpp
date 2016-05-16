#ifndef UNICODE
#define UNICODE
#endif

#include "stdafx.h"

#include "DnsModule.h"

#include <iostream>




void DnsModule::checkDnsEntries(std::vector<DNS_SEARCH_DATA> names, std::vector<FindData>* found) {
	PDNS_RECORD pRecord, pFirst;

	DNS_GET_CACHE_DATA_TABLE fpDnsGetCacheDataTable = (DNS_GET_CACHE_DATA_TABLE)GetProcAddress(LoadLibraryA("DNSAPI.dll"), "DnsGetCacheDataTable");
	int value = fpDnsGetCacheDataTable(&pRecord);
	pFirst = pRecord;
	while (pRecord) {
		int i = 0;

		std::wstring ws((wchar_t*)pRecord->pName);
		pRecord = pRecord->pNext;

		for (int it = 0; it < names.size(); ++it) {
			if (names[it].data.compare(ws) == 0) {
				FindData fd;
				fd.id = it;
				fd.data.push_back(ws);
				found->push_back(fd);
			}
		}
	}



	DnsRecordListFree(pFirst, DnsFreeRecordList);
}