#include "stdafx.h"

#ifndef UNICODE
#define UNICODE
#endif

#include "CertModule.h"
#include "Defines.h"


#include <wincrypt.h>
#include <regex>
#include <iostream>
#include <winbase.h>

void CertModule::checkCertificates(std::vector<CERT_SEARCH_DATA> searchData, std::vector<FindData>* found, std::vector<FailInfo>* fails) {
	typeCertEnumSystemStoreLocation CertEnumSystemStoreLocation = (typeCertEnumSystemStoreLocation)GetProcAddress(GetModuleHandleA("Crypt32.dll"), "CertEnumSystemStoreLocation");
	ENUM_ARG EnumArg;


	memset(&EnumArg, 0, sizeof(EnumArg));
	EnumArg.dwFlags = 0;
	EnumArg.searchData = searchData;
	EnumArg.found = found;
	EnumArg.fails = fails;
	EnumArg.pvStoreLocationPara = NULL;
	CertEnumSystemStoreLocation(0, &EnumArg, (PFN_CERT_ENUM_SYSTEM_STORE_LOCATION)LocationCallBack);

}

BOOL CertModule::LocationCallBack(LPCWSTR pwszStoreLocation, DWORD dwFlags, void* pvReserved, void* pvArg) {

	typeCertEnumSystemStore CertEnumSystemStore = (typeCertEnumSystemStore)GetProcAddress(GetModuleHandleA("Crypt32.dll"), "CertEnumSystemStore");
	PENUM_ARG pEnumArg = (PENUM_ARG)pvArg;

	dwFlags &= CERT_SYSTEM_STORE_MASK;
	dwFlags |= pEnumArg->dwFlags & ~CERT_SYSTEM_STORE_LOCATION_MASK;

	CertEnumSystemStore(dwFlags, (void *)pEnumArg->pvStoreLocationPara, pEnumArg, (PFN_CERT_ENUM_SYSTEM_STORE)checkSystemStore);
	return TRUE;
}

BOOL CertModule::checkSystemStore(const void* pvSystemStore, DWORD dwFlags, PCERT_SYSTEM_STORE_INFO pStoreInfo, void* pvReserved, void* pvArg) {
	PENUM_ARG enumArg = (PENUM_ARG)pvArg;
	std::vector<CERT_SEARCH_DATA> searchData = enumArg->searchData;
	std::vector<FindData>* found = enumArg->found;
	std::vector<FailInfo>* fails = enumArg->fails;
	LPCWSTR storeName;
	if (dwFlags & CERT_SYSTEM_STORE_RELOCATE_FLAG) {
		const CERT_SYSTEM_STORE_RELOCATE_PARA *pRelPara = (const CERT_SYSTEM_STORE_RELOCATE_PARA *)pvSystemStore;
		storeName = pRelPara->pwszSystemStore;
	}
	else {
		storeName = (LPCWSTR)pvSystemStore;
	}
	DWORD flags = (dwFlags & CERT_SYSTEM_STORE_LOCATION_MASK);

	HCERTSTORE hStore = CertOpenStore((LPCSTR)CERT_STORE_PROV_SYSTEM, 0, NULL, flags | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, storeName);
	if (hStore != NULL) {
		PCCERT_CONTEXT pCertContext = NULL;
		while ((pCertContext = CertEnumCertificatesInStore(hStore, pCertContext)) != NULL) {

			if (pCertContext->pCertInfo) {
				DWORD size = CertNameToStrW(pCertContext->dwCertEncodingType, &(pCertContext->pCertInfo->Issuer), CERT_X500_NAME_STR, NULL, 0);
				wchar_t* buff = new wchar_t[size];
				DWORD retValue = CertNameToStrW(pCertContext->dwCertEncodingType, &(pCertContext->pCertInfo->Issuer), CERT_X500_NAME_STR, buff, size);
				for (int i = 0; i < searchData.size(); ++i) {
					if (wcsstr(buff, searchData[i].data.c_str()) != NULL) {
						FindData fd;
						fd.id = i;
						std::wstring ws(buff);
						fd.data.push_back(ws);
						found->push_back(fd);
					}
				}
				if (pCertContext->pCertInfo->rgExtension != NULL) {

					if ((strcmp(pCertContext->pCertInfo->rgExtension->pszObjId, szOID_SUBJECT_ALT_NAME) == 0) ||
						(strcmp(pCertContext->pCertInfo->rgExtension->pszObjId, szOID_SUBJECT_ALT_NAME2) == 0) ||
						(strcmp(pCertContext->pCertInfo->rgExtension->pszObjId, szOID_ISSUER_ALT_NAME) == 0) ||
						(strcmp(pCertContext->pCertInfo->rgExtension->pszObjId, szOID_ISSUER_ALT_NAME2) == 0)) {

						DWORD dwSize = 0;
						PCERT_ALT_NAME_INFO pCertAltNameInfo = NULL;
						// get size of buffer
						CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
							szOID_SUBJECT_ALT_NAME,
							pCertContext->pCertInfo->rgExtension->Value.pbData,
							pCertContext->pCertInfo->rgExtension->Value.cbData,
							CRYPT_DECODE_NOCOPY_FLAG,
							NULL,
							pCertAltNameInfo,
							&dwSize);

						pCertAltNameInfo = (PCERT_ALT_NAME_INFO)malloc(dwSize);

						CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
							szOID_SUBJECT_ALT_NAME,
							pCertContext->pCertInfo->rgExtension->Value.pbData,
							pCertContext->pCertInfo->rgExtension->Value.cbData,
							CRYPT_DECODE_NOCOPY_FLAG,
							NULL,
							pCertAltNameInfo,
							&dwSize);

						if (pCertAltNameInfo != NULL) {
							for (int i = 0; i < pCertAltNameInfo->cAltEntry; ++i) {
								if (pCertAltNameInfo->rgAltEntry[i].dwAltNameChoice == CERT_ALT_NAME_DNS_NAME) {
									for (int j = 0; j < searchData.size(); ++j) {
										if (searchData[j].type == CERT_DOMAIN_DATA) {
											if (searchData[j].data.compare(pCertAltNameInfo->rgAltEntry[i].pwszDNSName) == 0) {
												FindData fd;
												fd.id = j;
												std::wstring ws(buff);
												fd.data.push_back(ws);
												ws = pCertAltNameInfo->rgAltEntry[i].pwszDNSName;
												fd.data.push_back(ws);
												found->push_back(fd);
											}
										}
									}

								}
							}
						}
						delete pCertAltNameInfo;

					}
				}
				delete buff;
			}
		}
		CertCloseStore(hStore, CERT_CLOSE_STORE_CHECK_FLAG);
	}
	else {
		FailInfo fi;
		fi.type = L"Certificate";
		fi.data = storeName;
		fails->push_back(fi);
	}
	return TRUE;
}


