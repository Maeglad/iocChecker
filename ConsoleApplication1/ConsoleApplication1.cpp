#include "stdafx.h"
#include "HashModule.h"
#include "Ioc-parser.h"
#include "CurlModule.h"
#include "DnsModule.h"
#include "OpenConnectionModule.h"
#include "MutantModule.h"
#include "CertModule.h"
#include "ProcessModule.h"
#include "RegistryModule.h"
#include "FileModule.h"
#include "Node.h"
#include "jsoncons/json.hpp"
#include <iostream>
#include <Windows.h>
#include <vector>
#include <string>
#include <sstream>
#include <queue>
#include <codecvt>
#include <io.h>
#include <fcntl.h>
#include <tchar.h>
#include <locale>

using namespace std;

void makeLog(vector<Node*> nodes, string testName, string url, string org, std::vector<FailInfo> fails);
void checkSystem(vector<Node*> nodes, bool checkIpv6, std::vector<FailInfo>* fails);
int main()
{
	// dolezita poznamka !!!! ak sa nastavi output console do tohto modu tak sa nesmie pouzivat cout aj wcout zaroven
	// moze sa pouzivat len jedna funkcia inak to padne
	_setmode(_fileno(stdout), _O_U16TEXT);

	vector<Node*> nodes;
	IocParser iocp;
	string op, setName, url, org;

	ifstream input;
	input.open("config.cfg", ifstream::in);
	
	input >> op;

	if (strcmp(op.c_str(), "server") == 0) {
		input >> url;
		input >> setName;
		CurlModule cMod;
		cMod.fetchDataFromServer(url, setName);
		string s = "./iocs/";
		s.append(setName.c_str());
		s.append(".txt");
		nodes = iocp.parseFile(s.c_str());
	}

	if (strcmp(op.c_str(), "local") == 0) {
		input >> setName;
		string s = "./iocs/";
		s.append(setName.c_str());
		s.append(".txt");
		//wcout << s.c_str() << endl;
		nodes = iocp.parseFile(s.c_str());
		
	}

	string ipv6Toggle;
	input >> ipv6Toggle;
	input >> org;
	if (nodes.empty()) {
		wcout << L"Failed to fetch IOCs from file." << endl;
		return 1;
	}

	bool ipv6 = true;

	if (ipv6Toggle.compare("Ipv6=no") == 0) {
		ipv6 = false;
	}
	std::vector<FailInfo> fails;
	checkSystem(nodes, ipv6, &fails);
	if (op.compare("server") == 0) {
		makeLog(nodes, setName, url, org, fails);
	}
	else {
		url = "";
		makeLog(nodes, setName, url, org, fails);
	}
	return 0;
}

void makeLog(vector<Node*> nodes, string testName, string url, string org, std::vector<FailInfo> fails) {

	jsoncons::wjson jsonbuilder;
	jsonbuilder.clear();
	wstring orgName, dev;
	orgName.append(org.begin(), org.end());
	wchar_t* devName = new wchar_t[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
	
	GetComputerNameW(devName, &size);
	dev.append(devName);
	jsonbuilder[L"org"] = orgName;
	jsonbuilder[L"dev"] = dev;
	jsonbuilder[L"Detected"] = nodes[0]->evaluate();
	jsonbuilder[L"timestamp"] = std::time(NULL);
	wstring name;
	name.append(testName.begin(), testName.end());
	jsonbuilder[L"set"] = name;
	jsoncons::wjson iocs = jsoncons::wjson::array();

	for (int i = 0; i < nodes.size(); ++i) {
		if (nodes[i]->priority < 10) {

			jsoncons::wjson j;
			j[L"id"] = nodes[i]->iocId;
			j[L"result"] = nodes[i]->found;
			jsoncons::wjson data = jsoncons::wjson::array();
			for (int k = 0; k < nodes[i]->fdata.size(); ++k) {
				data.add(nodes[i]->fdata[k]);
			}
			j[L"data"] = data;

			iocs.add(j);

		}
	}
	jsoncons::wjson failDataReg = jsoncons::wjson::array();
	jsoncons::wjson failDataCert = jsoncons::wjson::array();
	for (int i = 0; i < fails.size(); ++i) {
		jsoncons::wjson dataReg, dataCert;
		if (fails[i].type.compare(L"Registry") == 0) {
			dataReg[L"data"] = fails[i].data;
			failDataReg.add(dataReg);
		}
		if (fails[i].type.compare(L"Certificate") == 0) {
			dataCert[L"data"] = fails[i].data;
			failDataCert.add(dataCert);
		}
		
	}
	jsoncons::wjson failData;
	failData[L"FailedRegistry"] = failDataReg;
	failData[L"FailedCertificate"] = failDataCert;
	jsonbuilder[L"FailedToOpen"] = failData;
	jsonbuilder[L"results"] = iocs;
	string s = "./logs/";
	s.append(testName.c_str());
	s.append(".log");
	wofstream file;
	jsoncons::woutput_format output;
	output.escape_all_non_ascii(true);
	wcout << jsoncons::pretty_print(jsonbuilder);
	file.open(s, wofstream::out | wofstream::trunc);
	file << jsoncons::pretty_print(jsonbuilder, output);
	file.close();
	if (url.compare("") != 0) {
		CurlModule cMod;
		cMod.uploadDataToServer(url, testName);
	}
}

struct NodeComparator {
	bool operator() (const Node* left, const Node* right) {
		return left->priority > right->priority;
	}
};

void checkSystem(vector<Node*> nodes, bool checkIpv6, std::vector<FailInfo>* fails) {
	priority_queue<Node*, vector<Node*>, NodeComparator> nodeQueue;
	


	for (int i = 0; i < nodes.size(); ++i) {
		if (nodes[i]->priority < 10) {
			nodeQueue.push(nodes[i]);
		}
	}
	while (nodeQueue.empty() == false) {
		Node* node = nodeQueue.top();
		int priority = node->priority;

		vector<Node*> workNodes;
		workNodes.clear();
		while ((nodeQueue.empty() == false) && (nodeQueue.top()->priority == priority)) {
			Node* wNode = nodeQueue.top();
			workNodes.push_back(wNode);
			nodeQueue.pop();
		}
		if (priority == 1) {
			
			wcout << L"Checking certificates." << endl;
			vector<CERT_SEARCH_DATA> searchData;
			vector<FindData> found;
			found.clear();
			for (int i = 0; i < workNodes.size(); ++i) {

				CERT_SEARCH_DATA search;
				search.found = false;
				search.iocId = workNodes[i]->index;
				search.type = workNodes[i]->dataId;
				search.data = workNodes[i]->data;

				searchData.push_back(search);
			}
			CertModule certModule;
			certModule.checkCertificates(searchData, &found, fails);

			for (int k = 0; k < found.size(); ++k) {

				nodes[searchData[found[k].id].iocId]->found = true;
				nodes[searchData[found[k].id].iocId]->fdata = found[k].data;
			}
			
			

		}

		if (priority == 2) {
			
			wcout << L"Checking connections." << endl;
			vector<CONNECTION_SEARCH_DATA> searchData;
			vector<FindData> found;
			found.clear();
			for (int i = 0; i < workNodes.size(); ++i) {

				CONNECTION_SEARCH_DATA search;
				search.found = false;
				search.iocId = workNodes[i]->index;
				search.type = workNodes[i]->dataId;
				search.data = workNodes[i]->data;

				searchData.push_back(search);
			}
			OpenConnectionModule connectModule;
			connectModule.checkConnections(searchData, &found);

			for (int k = 0; k < found.size(); ++k) {
				nodes[searchData[found[k].id].iocId]->found = true;
				nodes[searchData[found[k].id].iocId]->fdata = found[k].data;
			}

			

		}
		if (priority == 3) {
			wcout << L"Checking DNS cache." << endl;
			vector<DNS_SEARCH_DATA> searchData;
			vector<FindData> found;
			found.clear();
			for (int i = 0; i < workNodes.size(); ++i) {

				DNS_SEARCH_DATA search;
				search.found = false;
				search.iocId = workNodes[i]->index;

				search.data = workNodes[i]->data;

				searchData.push_back(search);
			}
			DnsModule dnsModule;
			dnsModule.checkDnsEntries(searchData, &found);

			for (int k = 0; k < found.size(); ++k) {
				nodes[searchData[found[k].id].iocId]->found = true;
				nodes[searchData[found[k].id].iocId]->fdata = found[k].data;
			}



		}

		if (priority == 4) {
			
			wcout << L"Checking mutexes." << endl;
			vector<MUTEX_SEARCH_DATA> searchData;
			vector<FindData> found;
			found.clear();
			for (int i = 0; i < workNodes.size(); ++i) {

				MUTEX_SEARCH_DATA search;
				search.found = false;
				search.iocId = workNodes[i]->index;

				search.data = workNodes[i]->data;

				searchData.push_back(search);
			}
			MutantModule mutantModule;
			mutantModule.checkMutexes(searchData, &found);

			for (int k = 0; k < found.size(); ++k) {
				nodes[searchData[found[k].id].iocId]->found = true;
				nodes[searchData[found[k].id].iocId]->fdata = found[k].data;
			}
			

		}

		if (priority == 5) {
			
			wcout << L"Checking processes." << endl;
			vector<PROCESS_SEARCH_DATA> searchData;
			vector<FindData> found;
			found.clear();
			for (int i = 0; i < workNodes.size(); ++i) {

				PROCESS_SEARCH_DATA search;
				search.found = false;
				search.iocId = workNodes[i]->index;
				search.dataId = workNodes[i]->dataId;
				search.data = workNodes[i]->data;

				searchData.push_back(search);
			}
			ProcessModule procModule;
			procModule.checkProcesses(searchData, &found);
			for (int k = 0; k < found.size(); ++k) {
				nodes[searchData[found[k].id].iocId]->found = true;
				nodes[searchData[found[k].id].iocId]->fdata = found[k].data;
			}

			

		}

		if (priority == 8) {
			
			wcout << L"Checking registry." << endl;
			vector<REGISTRY_SEARCH_DATA> searchData;
			vector<FindData> found;
			found.clear();
			for (int i = 0; i < workNodes.size(); ++i) {
				RegistryNode* regNode = (RegistryNode*)workNodes[i];
				REGISTRY_SEARCH_DATA search;
				search.found = false;
				search.iocId = regNode->index;
				search.dataId = regNode->dataId;
				search.name = regNode->name;
				search.valueName = regNode->valueName;
				search.valueValue = regNode->valueValue;

				searchData.push_back(search);
			}
			RegistryModule regModule;
			regModule.checkRegistry(searchData, &found, fails);

			for (int k = 0; k < found.size(); ++k) {
				nodes[searchData[found[k].id].iocId]->found = true;
				nodes[searchData[found[k].id].iocId]->fdata = found[k].data;
			}
			


		}

		if (priority == 9) {
			
			wcout << L"Checking files." << endl;
			vector<FILE_SEARCH_DATA> searchData;
			vector<FindData> found;
			found.clear();
			for (int i = 0; i < workNodes.size(); ++i) {
				FileNode* fileNode = (FileNode*)workNodes[i];
				FILE_SEARCH_DATA search;
				search.found = false;
				search.iocId = fileNode->index;
				search.dataId = fileNode->dataId;
				search.path = fileNode->path;
				search.name = fileNode->name;
				search.hashType = fileNode->hashType;
				search.hash = fileNode->hash;

				searchData.push_back(search);
			}
			FileModule fileModule;
			fileModule.checkForFiles(searchData, &found);

			for (int k = 0; k < found.size(); ++k) {
				nodes[searchData[found[k].id].iocId]->found = true;
				nodes[searchData[found[k].id].iocId]->fdata = found[k].data;
			}
			
			
		}

	}
}
