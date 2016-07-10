#pragma once

#ifndef OPENCONNECTIONMODULE_H
#define OPENCONNECTIONMODULE_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#include <windows.h>
#include <ws2tcpip.h>
#include <vector>
#include <string>
#include <iphlpapi.h>
#include "Defines.h"
#define CONNECTION_IP_DATA 1
#define CONNECTION_DOMAIN_DATA 2
#define CONNECTION_DOMAIN_REGEX_DATA 3

typedef struct _CONNECTION_SEARCH_DATA {
	int iocId;
	int type;
	std::wstring data;
	bool found;
} CONNECTION_SEARCH_DATA;

typedef struct _MIB_TCP6ROW_EX {
	UCHAR ucLocalAddr[16];
	DWORD dwLocalScopeId;
	DWORD dwLocalPort;
	UCHAR ucRemoteAddr[16];
	DWORD dwRemoteScopeId;
	DWORD dwRemotePort;
	DWORD dwState;
	DWORD dwProcessId;
} MIB_TCP6ROW_EX, *PMIB_TCP6ROW_EX;

typedef struct _MIB_TCP6TABLE_EX {
	DWORD dwNumEntries;
	MIB_TCP6ROW_EX table[1];
} MIB_TCP6TABLE_EX, *PMIB_TCP6TABLE_EX;

typedef struct _MIB_UDP6ROW_EX {
	UCHAR ucLocalAddr[16];
	DWORD dwLocalScopeId;
	DWORD dwLocalPort;
	DWORD dwProcessId;
} MIB_UDP6ROW_EX, *PMIB_UDP6ROW_EX;

typedef struct _MIB_UDP6TABLE_EX {
	DWORD dwNumEntries;
	MIB_UDP6ROW_EX table[1];
} MIB_UDP6TABLE_EX, *PMIB_UDP6TABLE_EX;


class OpenConnectionModule {
public:
	void checkConnections(std::vector<CONNECTION_SEARCH_DATA> searchData, std::vector<FindData>* found);
private:
	void checkTcpIpv4Connections(std::vector<CONNECTION_SEARCH_DATA> searchData, std::vector<FindData>* found);
	void checkTcpIpv6Connections(std::vector<CONNECTION_SEARCH_DATA> searchData, std::vector<FindData>* found);
	void checkUdpIpv4Connections(std::vector<CONNECTION_SEARCH_DATA> searchData, std::vector<FindData>* found);
	void checkUdpIpv6Connections(std::vector<CONNECTION_SEARCH_DATA> searchData, std::vector<FindData>* found);
	bool oldImp();
	bool checkIpv6();
	typedef int (WSAAPI *typeGetNameInfoW)(
		const SOCKADDR  *pSockaddr,
		socklen_t SockaddrLength,
		PWCHAR    pNodeBuffer,
		DWORD     NodeBufferSize,
		PWCHAR    pServiceBuffer,
		DWORD     ServiceBufferSize,
		INT       Flags
		);

	typedef enum {
		UDP_TABLE_BASIC,
		UDP_TABLE_OWNER_PID,
		UDP_TABLE_OWNER_MODULE
	} UDP_TABLE_CLASS, *PUDP_TABLE_CLASS;

	typedef DWORD(WINAPI *typeGetExtendedUdpTable)(
		PVOID           pUdpTable,
		PDWORD          pdwSize,
		BOOL            bOrder,
		ULONG           ulAf,
		UDP_TABLE_CLASS TableClass,
		ULONG           Reserved
		);

	typedef DWORD(WINAPI *typeGetExtendedTcpTable)(
		PVOID           pTcpTable,
		PDWORD          pdwSize,
		BOOL            bOrder,
		ULONG           ulAf,
		TCP_TABLE_CLASS TableClass,
		ULONG           Reserved
		);
	
	typedef DWORD(WINAPI *typeAllocateAndGetTcpExTableFromStack)(PVOID *ppTcpTable, BOOL bOrder, HANDLE hHeap, DWORD dwFlags, DWORD dwFamily);
	typedef DWORD(WINAPI *typeAllocateAndGetUdpExTableFromStack)(PVOID *ppUDPTable, BOOL bOrder, HANDLE hHeap, DWORD dwFlags, DWORD dwFamily);


};

#endif /* OPENCONNECTIONMODULE_H */

