#include "stdafx.h"
#include "OpenConnectionModule.h"

#define NI_MAXSERV    32
#define NI_MAXHOST  1025

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <ws2spi.h>

#include <cstdlib>
#include <stdio.h>
#include <string>
#include <vector>
#include <regex>

#include <iostream>
#include "sdkddkver.h"
#include "VersionHelpers.h"


void OpenConnectionModule::checkConnections(std::vector<CONNECTION_SEARCH_DATA> searchData, std::vector<FindData>* found) {
	WSADATA wsadata;
	WSAStartup(MAKEWORD(2, 2), &wsadata);
	std::wcout << L"TcpIPv4" << std::endl;
	checkTcpIpv4Connections(searchData, found);
	std::wcout << L"UdpIPv4" << std::endl;
	checkUdpIpv4Connections(searchData, found);
	if (checkIpv6()) {
		std::wcout << L"UdpIPv6" << std::endl;
		checkUdpIpv6Connections(searchData, found);
		std::wcout << L"TcpIPv6" << std::endl;
		checkTcpIpv6Connections(searchData, found);
	}
	else {
		std::wcout << L"Ipv6 skiped" << std::endl; 
	}
	WSACleanup();
}

bool OpenConnectionModule::checkIpv6() {
	DWORD dwBufferLen = 0;
	int errNo, retVal;
	retVal = WSCEnumProtocols(NULL, NULL, &dwBufferLen, &errNo);
	LPWSAPROTOCOL_INFOW lpProtocolInfo = NULL;
	lpProtocolInfo = (LPWSAPROTOCOL_INFOW)malloc(dwBufferLen);
	retVal = WSCEnumProtocols(NULL, lpProtocolInfo, &dwBufferLen, &errNo);

	if (retVal == SOCKET_ERROR) {
		return false;
	}

	for (int i = 0; i < retVal; ++i) {
		if (lpProtocolInfo[i].iAddressFamily == AF_INET6) return true;
	}

	return false;
}

bool OpenConnectionModule::oldImp() {
	if (IsWindowsServer() == false) {
		if (IsWindowsVistaOrGreater()) {
			return false;
		}
		else {
			return true;
		}

	}
	else {
		// je to server
		if (IsWindowsXPSP3OrGreater()) {// podla wiki to ma byt server 2008 treba overit !!!
			return false;
		}
		else {
			return true;
		}
	}
}


void OpenConnectionModule::checkTcpIpv4Connections(std::vector<CONNECTION_SEARCH_DATA> searchData, std::vector<FindData>* found) {
	bool isOldOs = oldImp();
	if (isOldOs) {
		DWORD dwSize = 0;
		GetTcpTable(NULL, &dwSize, true);

		PMIB_TCPTABLE pTcpTable = (PMIB_TCPTABLE)malloc(dwSize);

		if (GetTcpTable(pTcpTable, &dwSize, true) != NO_ERROR) {
			std::wcout << L"ERROR" << std::endl;
			return;
		}

		for (int i = 0; i < pTcpTable->dwNumEntries; ++i) {

			struct sockaddr_in sAddrIn;
			sAddrIn.sin_family = AF_INET;
			sAddrIn.sin_addr.s_addr = pTcpTable->table[i].dwLocalAddr;
			sAddrIn.sin_port = (u_short)pTcpTable->table[i].dwLocalPort;

			char* hostName = new char[NI_MAXHOST];
			char* hostAddress = new char[NI_MAXHOST];
			char* serviceName = new char[NI_MAXSERV];
			wchar_t* hostNameW = new wchar_t[NI_MAXHOST];
			bool resolved = false;
			wchar_t* hostAddressW = new wchar_t[NI_MAXHOST];
			wchar_t* serviceNameW = new wchar_t[NI_MAXSERV];
			getnameinfo((struct sockaddr *) &sAddrIn, sizeof(sockaddr_in), hostAddress, NI_MAXHOST, serviceName, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);


			mbstowcs(hostAddressW, hostAddress, NI_MAXHOST);

			for (int j = 0; j < searchData.size(); ++j) {
				if (searchData[j].found)continue;
				// addresa
				if (searchData[j].type == CONNECTION_IP_DATA) {
					if (searchData[j].data.compare(hostAddressW) == 0) {

						FindData fd;
						fd.id = j;
						std::wstring ws(hostAddressW);
						fd.data.push_back(hostAddressW);
						found->push_back(fd);
					}
				}
				// domena
				if (searchData[j].type == CONNECTION_DOMAIN_DATA) {
					if (resolved == false) {
						getnameinfo((struct sockaddr *) &sAddrIn, sizeof(sockaddr_in), hostName, NI_MAXHOST, serviceName, NI_MAXSERV, NI_NUMERICSERV);
						mbstowcs(hostNameW, hostName, NI_MAXHOST);
						resolved = true;
					}
					if (searchData[j].data.compare(hostNameW) == 0) {

						FindData fd;
						fd.id = j;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}

				if (searchData[j].type == CONNECTION_DOMAIN_REGEX_DATA) {
					std::wregex e(searchData[j].data);
					if (resolved == false) {
						getnameinfo((struct sockaddr *) &sAddrIn, sizeof(sockaddr_in), hostName, NI_MAXHOST, serviceName, NI_MAXSERV, NI_NUMERICSERV);
						mbstowcs(hostNameW, hostName, NI_MAXHOST);
						resolved = true;
					}
					if (std::regex_match(hostNameW, e)) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}
			}



			sAddrIn.sin_family = AF_INET;
			sAddrIn.sin_addr.s_addr = pTcpTable->table[i].dwRemoteAddr;
			sAddrIn.sin_port = (u_short)pTcpTable->table[i].dwRemotePort;
			resolved = false;
			getnameinfo((struct sockaddr *) &sAddrIn, sizeof(sockaddr_in), hostAddress, NI_MAXHOST, serviceName, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);

			mbstowcs(hostAddressW, hostAddress, NI_MAXHOST);

			for (int j = 0; j < searchData.size(); ++j) {
				if (searchData[j].found)continue;
				// addresa
				if (searchData[j].type == CONNECTION_IP_DATA) {
					if (searchData[j].data.compare(hostAddressW) == 0) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostAddressW);
						fd.data.push_back(hostAddressW);
						found->push_back(fd);
					}
				}
				// domena
				if (searchData[j].type == CONNECTION_DOMAIN_DATA) {
					if (resolved == false) {
						getnameinfo((struct sockaddr *) &sAddrIn, sizeof(sockaddr_in), hostName, NI_MAXHOST, serviceName, NI_MAXSERV, NI_NUMERICSERV);
						mbstowcs(hostNameW, hostName, NI_MAXHOST);
						resolved = true;
					}
					if (searchData[j].data.compare(hostNameW) == 0) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}

				if (searchData[j].type == CONNECTION_DOMAIN_REGEX_DATA) {
					std::wregex e(searchData[j].data);
					if (resolved == false) {
						getnameinfo((struct sockaddr *) &sAddrIn, sizeof(sockaddr_in), hostName, NI_MAXHOST, serviceName, NI_MAXSERV, NI_NUMERICSERV);
						mbstowcs(hostNameW, hostName, NI_MAXHOST);
						resolved = true;
					}
					if (std::regex_match(hostNameW, e)) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}
			}

			delete hostName, hostAddress, serviceName, hostNameW, hostAddressW, serviceNameW;


		}
		delete pTcpTable;

	}
	else {
		typeGetNameInfoW GetNameInfoW = (typeGetNameInfoW)GetProcAddress(LoadLibraryW(L"Ws2_32.dll"), "GetNameInfoW");
		typeGetExtendedTcpTable GetExtendedTcpTable = (typeGetExtendedTcpTable)GetProcAddress(LoadLibrary(L"iphlpapi.dll"), "GetExtendedTcpTable");
		if (GetNameInfoW == NULL) {
			std::wcout << L"ERROR";
			return;
		}
		DWORD dwSize = 0;
		PMIB_TCPTABLE pTcpTable;
		// get size
		GetExtendedTcpTable(NULL, &dwSize, false, AF_INET, TCP_TABLE_BASIC_ALL, 0);
		//alloc
		pTcpTable = (MIB_TCPTABLE *)malloc(dwSize);
		//get Table
		if (GetExtendedTcpTable(pTcpTable, &dwSize, true, AF_INET, TCP_TABLE_BASIC_ALL, 0) != NO_ERROR) return;

		// enum

		for (int j = 0; j < pTcpTable->dwNumEntries; ++j) {

			struct sockaddr_in sAddrIn;
			sAddrIn.sin_family = AF_INET;
			sAddrIn.sin_addr.s_addr = pTcpTable->table[j].dwLocalAddr;
			sAddrIn.sin_port = (u_short)pTcpTable->table[j].dwLocalPort;
			wchar_t* hostNameW = new wchar_t[NI_MAXHOST];
			wchar_t* hostAddressW = new wchar_t[NI_MAXHOST];
			wchar_t* serviceNameW = new wchar_t[NI_MAXSERV];
			bool resolved = false;
			GetNameInfoW((struct sockaddr *) &sAddrIn, sizeof(sockaddr_in), hostAddressW, NI_MAXHOST, serviceNameW, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);

			for (int i = 0; i < searchData.size(); ++i) {
				if (searchData[i].found)continue;
				// addresa
				if (searchData[i].type == CONNECTION_IP_DATA) {
					if (searchData[i].data.compare(hostAddressW) == 0) {
						FindData fd;
						fd.id = i;
						std::wstring ws(hostAddressW);
						fd.data.push_back(hostAddressW);
						found->push_back(fd);
					}
				}
				// domena
				if (searchData[i].type == CONNECTION_DOMAIN_DATA) {
					if (resolved == false) {
						GetNameInfoW((struct sockaddr *) &sAddrIn, sizeof(sockaddr_in), hostNameW, NI_MAXHOST, serviceNameW, NI_MAXSERV, NI_NUMERICSERV);
						resolved = true;
					}
					if (searchData[i].data.compare(hostNameW) == 0) {
						FindData fd;
						fd.id = i;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}
				// domena regex
				if (searchData[i].type == CONNECTION_DOMAIN_REGEX_DATA) {
					if (resolved == false) {
						GetNameInfoW((struct sockaddr *) &sAddrIn, sizeof(sockaddr_in), hostNameW, NI_MAXHOST, serviceNameW, NI_MAXSERV, NI_NUMERICSERV);
						resolved = true;
					}
					std::wregex e(searchData[i].data);
					if (std::regex_match(hostNameW, e)) {
						FindData fd;
						fd.id = i;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}

			}


			sAddrIn.sin_family = AF_INET;
			sAddrIn.sin_addr.s_addr = pTcpTable->table[j].dwRemoteAddr;
			sAddrIn.sin_port = (u_short)pTcpTable->table[j].dwRemotePort;
			resolved = false;
			GetNameInfoW((struct sockaddr *) &sAddrIn, sizeof(sockaddr_in), hostAddressW, NI_MAXHOST, serviceNameW, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);

			for (int i = 0; i < searchData.size(); ++i) {

				if (searchData[i].found)continue;
				// addresa
				if (searchData[i].type == CONNECTION_IP_DATA) {
					if (searchData[i].data.compare(hostAddressW) == 0) {
						FindData fd;
						fd.id = i;
						std::wstring ws(hostAddressW);
						fd.data.push_back(hostAddressW);
						found->push_back(fd);
					}
				}
				// domena
				if (searchData[i].type == CONNECTION_DOMAIN_DATA) {
					if (resolved == false) {
						GetNameInfoW((struct sockaddr *) &sAddrIn, sizeof(sockaddr_in), hostNameW, NI_MAXHOST, serviceNameW, NI_MAXSERV, NI_NUMERICSERV);
						resolved = true;
					}
					//std::wcout << hostNameW << std::endl;
					if (searchData[i].data.compare(hostNameW) == 0) {
						FindData fd;
						fd.id = i;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}
				// domena regex
				if (searchData[i].type == CONNECTION_DOMAIN_REGEX_DATA) {
					if (resolved == false) {
						GetNameInfoW((struct sockaddr *) &sAddrIn, sizeof(sockaddr_in), hostNameW, NI_MAXHOST, serviceNameW, NI_MAXSERV, NI_NUMERICSERV);
						resolved = true;
					}
					std::wregex e(searchData[i].data);
					if (std::regex_match(hostNameW, e)) {
						FindData fd;
						fd.id = i;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}

			}

			delete hostNameW, serviceNameW, hostAddressW;

		}
		delete pTcpTable;

	}
}

void OpenConnectionModule::checkTcpIpv6Connections(std::vector<CONNECTION_SEARCH_DATA> searchData, std::vector<FindData>* found) {
	bool isOldOs = oldImp();
	if (isOldOs) {
		HANDLE hProcessHeap = GetProcessHeap();
		if (hProcessHeap == NULL) {

			return;
		}

		typeAllocateAndGetTcpExTableFromStack AllocateAndGetTcpExTableFromStack = NULL;
		AllocateAndGetTcpExTableFromStack = (typeAllocateAndGetTcpExTableFromStack)GetProcAddress(LoadLibraryA("iphlpapi.dll"), "AllocateAndGetTcpExTableFromStack");

		if (AllocateAndGetTcpExTableFromStack == NULL) {
			std::wcout << L"ERROR" << std::endl;
			return;
		}

		PMIB_TCP6TABLE_EX pTcpTable;

		AllocateAndGetTcpExTableFromStack((PVOID*)&pTcpTable, true, hProcessHeap, 0, 23);

		for (int i = 0; i < pTcpTable->dwNumEntries; ++i) {

			struct sockaddr_in6 inAddr;
			inAddr.sin6_family = AF_INET6;
			inAddr.sin6_port = pTcpTable->table[i].dwLocalPort;

			memcpy(inAddr.sin6_addr._S6_un._S6_u8, pTcpTable->table[i].ucLocalAddr, sizeof(inAddr.sin6_addr._S6_un._S6_u8));
			inAddr.sin6_scope_id = pTcpTable->table[i].dwLocalScopeId;
			char* hostName = new char[NI_MAXHOST];
			char* hostAddress = new char[NI_MAXHOST];
			char* serviceName = new char[NI_MAXSERV];
			wchar_t* hostNameW = new wchar_t[NI_MAXHOST];
			wchar_t* hostAddressW = new wchar_t[NI_MAXHOST];
			wchar_t* serviceNameW = new wchar_t[NI_MAXSERV];
			bool resolved = false;
			getnameinfo((struct sockaddr *) &inAddr, sizeof(sockaddr_in6), hostAddress, NI_MAXHOST, serviceName, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);

			mbstowcs(hostAddressW, hostAddress, NI_MAXHOST);
			mbstowcs(serviceNameW, serviceName, NI_MAXHOST);

			for (int j = 0; j < searchData.size(); ++j) {

				if (searchData[j].found)continue;
				// addresa
				if (searchData[j].type == CONNECTION_IP_DATA) {
					if (searchData[j].data.compare(hostAddressW) == 0) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostAddressW);
						fd.data.push_back(hostAddressW);
						found->push_back(fd);
					}
				}
				// domena
				if (searchData[j].type == CONNECTION_DOMAIN_DATA) {
					if (resolved == false) {
						getnameinfo((struct sockaddr *) &inAddr, sizeof(sockaddr_in6), hostName, NI_MAXHOST, serviceName, NI_MAXSERV, NI_NUMERICSERV);
						mbstowcs(hostNameW, hostName, NI_MAXHOST);
						resolved = true;
					}
					if (searchData[j].data.compare(hostNameW) == 0) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}

				if (searchData[j].type == CONNECTION_DOMAIN_REGEX_DATA) {
					if (resolved == false) {
						getnameinfo((struct sockaddr *) &inAddr, sizeof(sockaddr_in6), hostName, NI_MAXHOST, serviceName, NI_MAXSERV, NI_NUMERICSERV);
						mbstowcs(hostNameW, hostName, NI_MAXHOST);
						resolved = true;
					}
					std::wregex e(searchData[j].data);
					if (std::regex_match(hostNameW, e)) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}
			}

			inAddr.sin6_family = AF_INET6;
			inAddr.sin6_port = pTcpTable->table[i].dwRemotePort;
			memcpy(inAddr.sin6_addr._S6_un._S6_u8, pTcpTable->table[i].ucRemoteAddr, sizeof(inAddr.sin6_addr._S6_un._S6_u8));
			inAddr.sin6_scope_id = pTcpTable->table[i].dwRemoteScopeId;
			resolved = false;
			getnameinfo((struct sockaddr *) &inAddr, sizeof(sockaddr_in6), hostAddress, NI_MAXHOST, serviceName, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);

			mbstowcs(hostAddressW, hostAddress, NI_MAXHOST);
			mbstowcs(serviceNameW, serviceName, NI_MAXHOST);

			for (int j = 0; j < searchData.size(); ++j) {

				if (searchData[j].found)continue;
				// addresa
				if (searchData[j].type == CONNECTION_IP_DATA) {
					if (searchData[j].data.compare(hostAddressW) == 0) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostAddressW);
						fd.data.push_back(hostAddressW);
						found->push_back(fd);
					}
				}
				// domena
				if (searchData[j].type == CONNECTION_DOMAIN_DATA) {
					if (resolved == false) {
						getnameinfo((struct sockaddr *) &inAddr, sizeof(sockaddr_in6), hostName, NI_MAXHOST, serviceName, NI_MAXSERV, NI_NUMERICSERV);
						mbstowcs(hostNameW, hostName, NI_MAXHOST);
						resolved = true;
					}
					if (searchData[j].data.compare(hostNameW) == 0) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}

				if (searchData[j].type == CONNECTION_DOMAIN_REGEX_DATA) {
					if (resolved == false) {
						getnameinfo((struct sockaddr *) &inAddr, sizeof(sockaddr_in6), hostName, NI_MAXHOST, serviceName, NI_MAXSERV, NI_NUMERICSERV);
						mbstowcs(hostNameW, hostName, NI_MAXHOST);
						resolved = true;
					}
					std::wregex e(searchData[j].data);
					if (std::regex_match(hostNameW, e)) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);;
					}
				}
			}

			delete hostAddress, hostAddressW, hostName, hostNameW, serviceName, serviceNameW;
		}

		delete pTcpTable;
	}
	else {

		typeGetNameInfoW GetNameInfoW = (typeGetNameInfoW)GetProcAddress(LoadLibraryW(L"Ws2_32.dll"), "GetNameInfoW");
		typeGetExtendedTcpTable GetExtendedTcpTable = (typeGetExtendedTcpTable)GetProcAddress(LoadLibrary(L"iphlpapi.dll"), "GetExtendedTcpTable");
		if (GetNameInfoW == NULL) {
			std::wcout << L"ERROR";
			return;
		}

		DWORD dwSize = 0;
		GetExtendedTcpTable(NULL, &dwSize, false, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
		PMIB_TCP6TABLE_OWNER_PID pTcp6Table = (MIB_TCP6TABLE_OWNER_PID *)malloc(dwSize);
		if (GetExtendedTcpTable(pTcp6Table, &dwSize, false, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)return;
		for (int i = 0; i < pTcp6Table->dwNumEntries; ++i) {
			struct sockaddr_in6 inAddr;
			memcpy(&inAddr.sin6_addr, pTcp6Table->table[i].ucLocalAddr, sizeof(inAddr.sin6_addr));
			inAddr.sin6_family = AF_INET6;
			inAddr.sin6_port = pTcp6Table->table[i].dwLocalPort;
			inAddr.sin6_scope_id = pTcp6Table->table[i].dwLocalScopeId;

			wchar_t* hostNameW = new wchar_t[NI_MAXHOST];
			wchar_t* hostAddressW = new wchar_t[NI_MAXHOST];
			wchar_t* serviceNameW = new wchar_t[NI_MAXSERV];
			bool resolved = false;
			GetNameInfoW((struct sockaddr *) &inAddr, sizeof(sockaddr_in6), hostAddressW, NI_MAXHOST, serviceNameW, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);

			for (int j = 0; j < searchData.size(); ++j) {

				if (searchData[j].found)continue;
				// addresa
				if (searchData[j].type == CONNECTION_IP_DATA) {
					if (searchData[j].data.compare(hostAddressW) == 0) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostAddressW);
						fd.data.push_back(hostAddressW);
						found->push_back(fd);
					}
				}
				// domena
				if (searchData[j].type == CONNECTION_DOMAIN_DATA) {
					if (resolved == false) {
						GetNameInfoW((struct sockaddr *) &inAddr, sizeof(sockaddr_in6), hostNameW, NI_MAXHOST, serviceNameW, NI_MAXSERV, NI_NUMERICSERV);
						resolved = true;
					}
					if (searchData[j].data.compare(hostNameW) == 0) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}

				if (searchData[j].type == CONNECTION_DOMAIN_REGEX_DATA) {
					if (resolved == false) {
						GetNameInfoW((struct sockaddr *) &inAddr, sizeof(sockaddr_in6), hostNameW, NI_MAXHOST, serviceNameW, NI_MAXSERV, NI_NUMERICSERV);
						resolved = true;
					}
					std::wregex e(searchData[j].data);
					if (std::regex_match(hostNameW, e)) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}
			}

			memcpy(&inAddr.sin6_addr, pTcp6Table->table[i].ucRemoteAddr, sizeof(inAddr.sin6_addr));
			inAddr.sin6_family = AF_INET6;
			inAddr.sin6_port = pTcp6Table->table[i].dwRemotePort;
			inAddr.sin6_scope_id = pTcp6Table->table[i].dwRemoteScopeId;
			resolved = false;
			GetNameInfoW((struct sockaddr *) &inAddr, sizeof(sockaddr_in6), hostAddressW, NI_MAXHOST, serviceNameW, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);

			for (int j = 0; j < searchData.size(); ++j) {

				if (searchData[j].found)continue;
				// addresa
				if (searchData[j].type == CONNECTION_IP_DATA) {
					if (searchData[j].data.compare(hostAddressW) == 0) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostAddressW);
						fd.data.push_back(hostAddressW);
						found->push_back(fd);
					}
				}
				// domena
				if (searchData[j].type == CONNECTION_DOMAIN_DATA) {
					if (resolved == false) {
						GetNameInfoW((struct sockaddr *) &inAddr, sizeof(sockaddr_in6), hostNameW, NI_MAXHOST, serviceNameW, NI_MAXSERV, NI_NUMERICSERV);
						resolved = true;
					}
					if (searchData[j].data.compare(hostNameW) == 0) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}

				if (searchData[j].type == CONNECTION_DOMAIN_REGEX_DATA) {
					if (resolved == false) {
						GetNameInfoW((struct sockaddr *) &inAddr, sizeof(sockaddr_in6), hostNameW, NI_MAXHOST, serviceNameW, NI_MAXSERV, NI_NUMERICSERV);
						resolved = true;
					}
					std::wregex e(searchData[j].data);
					if (std::regex_match(hostNameW, e)) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}
			}


		}


		delete pTcp6Table;

	}

}

void OpenConnectionModule::checkUdpIpv4Connections(std::vector<CONNECTION_SEARCH_DATA> searchData, std::vector<FindData>* found) {
	bool isOldOs = oldImp();
	if (isOldOs) {
		PMIB_UDPTABLE pUdpTable;
		DWORD dwSize = 0;
		GetUdpTable(NULL, &dwSize, false);

		pUdpTable = (MIB_UDPTABLE *)malloc(dwSize);
		if (GetUdpTable(pUdpTable, &dwSize, false) != NO_ERROR);
		for (int i = 0; i < pUdpTable->dwNumEntries; ++i) {
			struct sockaddr_in sAddrIn;
			sAddrIn.sin_family = AF_INET;
			sAddrIn.sin_addr.s_addr = pUdpTable->table[i].dwLocalAddr;
			sAddrIn.sin_port = (u_short)pUdpTable->table[i].dwLocalPort;

			char* hostName = new char[NI_MAXHOST];
			char* hostAddress = new char[NI_MAXHOST];
			char* serviceName = new char[NI_MAXSERV];
			wchar_t* hostNameW = new wchar_t[NI_MAXHOST];
			wchar_t* hostAddressW = new wchar_t[NI_MAXHOST];
			wchar_t* serviceNameW = new wchar_t[NI_MAXSERV];
			bool resolved = false;
			getnameinfo((struct sockaddr *) &sAddrIn, sizeof(sockaddr_in), hostAddress, NI_MAXHOST, serviceName, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);

			mbstowcs(hostAddressW, hostAddress, NI_MAXHOST);
			mbstowcs(serviceNameW, serviceName, NI_MAXHOST);

			for (int j = 0; j < searchData.size(); ++j) {
				if (searchData[j].found)continue;
				// addresa
				if (searchData[j].type == CONNECTION_IP_DATA) {
					if (searchData[j].data.compare(hostAddressW) == 0) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostAddressW);
						fd.data.push_back(hostAddressW);
						found->push_back(fd);
					}
				}
				// domena
				if (searchData[j].type == CONNECTION_DOMAIN_DATA) {
					if (resolved == false) {
						getnameinfo((struct sockaddr *) &sAddrIn, sizeof(sockaddr_in), hostName, NI_MAXHOST, serviceName, NI_MAXSERV, NI_NUMERICSERV);
						mbstowcs(hostNameW, hostName, NI_MAXHOST);
						resolved = true;
					}
					if (searchData[j].data.compare(hostNameW) == 0) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}

				if (searchData[j].type == CONNECTION_DOMAIN_REGEX_DATA) {
					if (resolved == false) {
						getnameinfo((struct sockaddr *) &sAddrIn, sizeof(sockaddr_in), hostName, NI_MAXHOST, serviceName, NI_MAXSERV, NI_NUMERICSERV);
						mbstowcs(hostNameW, hostName, NI_MAXHOST);
						resolved = true;
					}
					std::wregex e(searchData[j].data);
					if (std::regex_match(hostNameW, e)) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}
			}

			delete hostName, hostAddress, serviceName, hostNameW, hostAddressW, serviceNameW;
		}

		delete pUdpTable;
	}
	else {
		PMIB_UDPTABLE pUdpTable;
		DWORD dwSize = 0;
		GetUdpTable(NULL, &dwSize, false);

		typeGetNameInfoW GetNameInfoW = (typeGetNameInfoW)GetProcAddress(LoadLibraryW(L"Ws2_32.dll"), "GetNameInfoW");
		if (GetNameInfoW == NULL) {
			std::wcout << L"ERROR";
			return;
		}

		pUdpTable = (MIB_UDPTABLE *)malloc(dwSize);
		if (GetUdpTable(pUdpTable, &dwSize, false) != NO_ERROR);
		for (int i = 0; i < pUdpTable->dwNumEntries; ++i) {
			struct sockaddr_in sAddrIn;
			sAddrIn.sin_family = AF_INET;
			sAddrIn.sin_addr.s_addr = pUdpTable->table[i].dwLocalAddr;
			sAddrIn.sin_port = (u_short)pUdpTable->table[i].dwLocalPort;

			wchar_t* hostNameW = new wchar_t[NI_MAXHOST];
			wchar_t* hostAddressW = new wchar_t[NI_MAXHOST];
			wchar_t* serviceNameW = new wchar_t[NI_MAXSERV];
			bool resolved = false;
			GetNameInfoW((struct sockaddr *) &sAddrIn, sizeof(sockaddr_in), hostAddressW, NI_MAXHOST, serviceNameW, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);

			for (int j = 0; j < searchData.size(); ++j) {

				if (searchData[j].found)continue;
				// addresa
				if (searchData[j].type == CONNECTION_IP_DATA) {
					if (searchData[j].data.compare(hostAddressW) == 0) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostAddressW);
						fd.data.push_back(hostAddressW);
						found->push_back(fd);
					}
				}
				// domena
				if (searchData[j].type == CONNECTION_DOMAIN_DATA) {
					if (resolved == false) {
						GetNameInfoW((struct sockaddr *) &sAddrIn, sizeof(sockaddr_in), hostNameW, NI_MAXHOST, serviceNameW, NI_MAXSERV, NI_NUMERICSERV);
						resolved = true;
					}
					if (searchData[j].data.compare(hostNameW) == 0) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}

				if (searchData[j].type == CONNECTION_DOMAIN_REGEX_DATA) {
					if (resolved == false) {
						GetNameInfoW((struct sockaddr *) &sAddrIn, sizeof(sockaddr_in), hostNameW, NI_MAXHOST, serviceNameW, NI_MAXSERV, NI_NUMERICSERV);
						resolved = true;
					}
					std::wregex e(searchData[j].data);
					if (std::regex_match(hostNameW, e)) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}
			}

			delete hostNameW, hostAddressW, serviceNameW;
		}

		delete pUdpTable;
	}
}

void OpenConnectionModule::checkUdpIpv6Connections(std::vector<CONNECTION_SEARCH_DATA> searchData, std::vector<FindData>* found) {
	bool isOldOs = oldImp();
	if (isOldOs) {
		HANDLE hHeap = GetProcessHeap();


		HANDLE hProcessHeap = GetProcessHeap();
		if (hProcessHeap == NULL) {

			return;
		}


		typeAllocateAndGetUdpExTableFromStack AllocateAndGetUdpExTableFromStack = NULL;
		AllocateAndGetUdpExTableFromStack = (typeAllocateAndGetUdpExTableFromStack)GetProcAddress(LoadLibraryA("iphlpapi.dll"), "AllocateAndGetUdpExTableFromStack");
		if (AllocateAndGetUdpExTableFromStack == NULL) {
			std::wcout << L"ERROR" << std::endl;
			return;
		}

		PMIB_UDP6TABLE_EX pUdpTable;

		AllocateAndGetUdpExTableFromStack((PVOID*)&pUdpTable, true, hProcessHeap, 0, AF_INET6);

		for (int i = 0; i < pUdpTable->dwNumEntries; ++i) {

			struct sockaddr_in6 inAddr;
			inAddr.sin6_family = AF_INET6;
			inAddr.sin6_port = pUdpTable->table[i].dwLocalPort;

			memcpy(inAddr.sin6_addr._S6_un._S6_u8, pUdpTable->table[i].ucLocalAddr, sizeof(inAddr.sin6_addr._S6_un._S6_u8));
			inAddr.sin6_scope_id = pUdpTable->table[i].dwLocalScopeId;
			char* hostName = new char[NI_MAXHOST];
			char* hostAddress = new char[NI_MAXHOST];
			char* serviceName = new char[NI_MAXSERV];
			wchar_t* hostNameW = new wchar_t[NI_MAXHOST];
			wchar_t* hostAddressW = new wchar_t[NI_MAXHOST];
			wchar_t* serviceNameW = new wchar_t[NI_MAXSERV];
			bool resolved = false;
			getnameinfo((struct sockaddr *) &inAddr, sizeof(sockaddr_in6), hostAddress, NI_MAXHOST, serviceName, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);

			mbstowcs(hostAddressW, hostAddress, NI_MAXHOST);
			mbstowcs(serviceNameW, serviceName, NI_MAXHOST);

			for (int j = 0; j < searchData.size(); ++j) {

				if (searchData[j].found)continue;
				// addresa
				if (searchData[j].type == CONNECTION_IP_DATA) {
					if (searchData[j].data.compare(hostAddressW) == 0) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostAddressW);
						fd.data.push_back(hostAddressW);
						found->push_back(fd);
					}
				}
				// domena
				if (searchData[j].type == CONNECTION_DOMAIN_DATA) {
					if (resolved == false) {
						getnameinfo((struct sockaddr *) &inAddr, sizeof(sockaddr_in6), hostName, NI_MAXHOST, serviceName, NI_MAXSERV, NI_NUMERICSERV);
						mbstowcs(hostNameW, hostName, NI_MAXHOST);
						resolved = true;
					}
					if (searchData[j].data.compare(hostNameW) == 0) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}

				if (searchData[j].type == CONNECTION_DOMAIN_REGEX_DATA) {
					if (resolved == false) {
						getnameinfo((struct sockaddr *) &inAddr, sizeof(sockaddr_in6), hostName, NI_MAXHOST, serviceName, NI_MAXSERV, NI_NUMERICSERV);
						mbstowcs(hostNameW, hostName, NI_MAXHOST);
						resolved = true;
					}
					std::wregex e(searchData[j].data);
					if (std::regex_match(hostNameW, e)) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}
			}

			delete hostAddress, hostAddressW, hostName, hostNameW, serviceName, serviceNameW;
		}

		delete pUdpTable;

	}
	else {
		typeGetNameInfoW GetNameInfoW = (typeGetNameInfoW)GetProcAddress(LoadLibraryW(L"Ws2_32.dll"), "GetNameInfoW");
		if (GetNameInfoW == NULL) {
			std::wcout << L"ERROR";
			return;
		}

		typeGetExtendedUdpTable GetExtendedUdpTable = (typeGetExtendedUdpTable)GetProcAddress(LoadLibraryW(L"Iphlpapi.dll"), "GetExtendedUdpTable");
		if (GetExtendedUdpTable == NULL) {
			std::wcout << L"ERROR";
			return;
		}
		DWORD dwSize = 0;
		GetExtendedUdpTable(NULL, &dwSize, true, AF_INET6, UDP_TABLE_BASIC, 0);
		PMIB_UDP6TABLE pUdp6Table = (PMIB_UDP6TABLE)malloc(dwSize);
		if (GetExtendedUdpTable(pUdp6Table, &dwSize, true, AF_INET6, UDP_TABLE_BASIC, 0) != NO_ERROR) {
			std::wcout << L"ERROR udpIpv6" << std::endl;
			return;
		}

		for (int i = 0; i < pUdp6Table->dwNumEntries; ++i) {
			struct sockaddr_in6 inAddr;
			inAddr.sin6_addr._S6_un = pUdp6Table->table[i].dwLocalAddr._S6_un;

			inAddr.sin6_family = AF_INET6;
			inAddr.sin6_port = pUdp6Table->table[i].dwLocalPort;
			inAddr.sin6_scope_id = pUdp6Table->table[i].dwLocalScopeId;
			wchar_t* hostNameW = new wchar_t[NI_MAXHOST];
			wchar_t* hostAddressW = new wchar_t[NI_MAXHOST];
			wchar_t* serviceNameW = new wchar_t[NI_MAXSERV];
			bool resolved = false;
			GetNameInfoW((struct sockaddr *) &inAddr, sizeof(sockaddr_in6), hostAddressW, NI_MAXHOST, serviceNameW, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);

			for (int j = 0; j < searchData.size(); ++j) {

				if (searchData[j].found)continue;
				// addresa
				if (searchData[j].type == CONNECTION_IP_DATA) {
					if (searchData[j].data.compare(hostAddressW) == 0) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostAddressW);
						fd.data.push_back(hostAddressW);
						found->push_back(fd);
					}
				}
				// domena
				if (searchData[j].type == CONNECTION_DOMAIN_DATA) {
					if (resolved == false) {
						GetNameInfoW((struct sockaddr *) &inAddr, sizeof(sockaddr_in6), hostNameW, NI_MAXHOST, serviceNameW, NI_MAXSERV, NI_NUMERICSERV);
						resolved = true;
					}
					if (searchData[j].data.compare(hostNameW) == 0) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}

				if (searchData[j].type == CONNECTION_DOMAIN_REGEX_DATA) {
					if (resolved == false) {
						GetNameInfoW((struct sockaddr *) &inAddr, sizeof(sockaddr_in6), hostNameW, NI_MAXHOST, serviceNameW, NI_MAXSERV, NI_NUMERICSERV);
						resolved = true;
					}
					std::wregex e(searchData[j].data);
					if (std::regex_match(hostNameW, e)) {
						FindData fd;
						fd.id = j;
						std::wstring ws(hostNameW);
						fd.data.push_back(hostNameW);
						found->push_back(fd);
					}
				}
			}


			delete hostAddressW, hostNameW, serviceNameW;
		}

		delete pUdp6Table;

	}

}

