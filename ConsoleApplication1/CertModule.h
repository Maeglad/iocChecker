#pragma once

#ifndef CERTMODULE_H
#define CERTMODULE_H

#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include "Defines.h"

#define CERT_DOMAIN_DATA 1
#define CERT_ISSUER_DATA 2
typedef struct _CERT_SEARCH_DATA {
	int iocId;
	int type;
	std::wstring data;
	bool found;
} CERT_SEARCH_DATA;

typedef struct _ENUM_ARG {
	DWORD       dwFlags;
	const void  *pvStoreLocationPara;
	std::vector<CERT_SEARCH_DATA> searchData;
	std::vector<FindData>* found;
	std::vector<FailInfo>* fails;
} ENUM_ARG, *PENUM_ARG;

//-------------------------------------------------------------------
// Copyright (C) Microsoft.  All rights reserved.
// Declare callback functions. 
// Definitions of these functions follow main.


#define CERT_SYSTEM_STORE_CURRENT_USER_ID          1
#define sz_CERT_STORE_PROV_SYSTEM_W                "System"
#define CERT_SYSTEM_STORE_LOCATION_MASK            0x00FF0000
#define CERT_SYSTEM_STORE_LOCATION_SHIFT           16
#define CERT_SYSTEM_STORE_MASK                     0xFFFF0000
#define CERT_SYSTEM_STORE_RELOCATE_FLAG            0x80000000
#define CERT_PHYSICAL_STORE_PREDEFINED_ENUM_FLAG   0x1

#define CERT_STORE_OPEN_EXISTING_FLAG 0x00004000
#define CERT_STORE_READONLY_FLAG 0x00008000


#define CERT_NAME_ISSUER_FLAG 0x1
#define CERT_CLOSE_STORE_CHECK_FLAG 0x00000002

#define CRYPT_DECODE_NOCOPY_FLAG 0x1

#define CERT_ALT_NAME_OTHER_NAME 1
#define CERT_ALT_NAME_RFC822_NAME 2
#define CERT_ALT_NAME_DNS_NAME 3
#define CERT_ALT_NAME_X400_ADDRESS 4
#define CERT_ALT_NAME_DIRECTORY_NAME 5
#define CERT_ALT_NAME_EDI_PARTY_NAME 6
#define CERT_ALT_NAME_URL 7
#define CERT_ALT_NAME_IP_ADDRESS 8
#define CERT_ALT_NAME_REGISTERED_ID 9

class CertModule {
public:
	void checkCertificates(std::vector<CERT_SEARCH_DATA> searchData, std::vector<FindData>* found, std::vector<FailInfo>* fails);
private:

	static std::vector<CERT_SEARCH_DATA> data;
	static std::vector<int>* f;

	typedef BOOL(*PFN_CERT_ENUM_SYSTEM_STORE)(
		const void* pvSystemStore,
		DWORD dwFlags,
		PCERT_SYSTEM_STORE_INFO pStoreInfo,
		void* pvReserved,
		void* pvArg
		);

	typedef BOOL(*PFN_CERT_ENUM_PHYSICAL_STORE)(
		const void* pvSystemStore,
		DWORD dwFlags,
		LPCWSTR pwszStoreName,
		PCERT_PHYSICAL_STORE_INFO pStoreInfo,
		void* pvReserved,
		void* pvArg
		);

	typedef BOOL(*PFN_CERT_ENUM_SYSTEM_STORE_LOCATION)(
		LPCWSTR pwszStoreLocation,
		DWORD dwFlags,
		void *pvReserved,
		void *pvArg
		);

	typedef BOOL(WINAPI *typeCertEnumSystemStoreLocation)(
		DWORD                               dwFlags,
		void                                *pvArg,
		PFN_CERT_ENUM_SYSTEM_STORE_LOCATION pfnEnum
		);

	typedef BOOL(WINAPI *typeCertEnumPhysicalStore)(
		const void                   *pvSystemStore,
		DWORD                        dwFlags,
		void                         *pvArg,
		PFN_CERT_ENUM_PHYSICAL_STORE pfnEnum
		);

	typedef BOOL(WINAPI *typeCertEnumSystemStore)(
		DWORD                      dwFlags,
		void                       *pvSystemStoreLocationPara,
		void                       *pvArg,
		PFN_CERT_ENUM_SYSTEM_STORE pfnEnum
		);

	static BOOL WINAPI LocationCallBack(
		LPCWSTR pwszStoreLocation,
		DWORD dwFlags,
		void *pvReserved,
		void *pvArg);

	static BOOL WINAPI checkSystemStore(const void *pvSystemStore, DWORD dwFlags, PCERT_SYSTEM_STORE_INFO pStoreInfo, void *pvReserved, void *pvArg);

};

#endif /* CERTMODULE_H */
