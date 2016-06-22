#include "stdafx.h"
#include "Ioc-parser.h"
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <io.h>
#include <fcntl.h>
#include <codecvt>
using jsoncons::wjson;
using namespace std;

std::vector<Node*> IocParser::parseFile(std::string filePath) {
	std::wifstream dataIn;
	dataIn.open(filePath.c_str(), std::wifstream::in);
	wjson root;
	dataIn >> root;
	vector<Node*> nodes;
	
	
	//std::wcout << jsoncons::pretty_print(root);
	
	wstring success = root.get(L"success").as<std::wstring>();
	if (success.compare(L"true") == 0) {
	}
	else { return nodes; }

	
	Node* rootNode = new Node;
	rootNode->iocId = 0;
	rootNode->priority = 11;
	rootNode->index = 0;
	rootNode->found = false;
	nodes.push_back(rootNode);
	
	

	wjson data = root.get(L"data", L"");

	for (int i = 0; i < data.size(); ++i) {

		Node* node = parseNode(data[i], &nodes);
		node->index = nodes.size();
		rootNode->children.push_back(node);
		nodes.push_back(node);
	}

	dataIn.close();
	return nodes;
}

Node* IocParser::parseNode(jsoncons::wjson data, vector<Node*>* nodes) {
	wstring type = data.get(L"type", L"nope").as<std::wstring>();

	if (type.compare(L"nope") == 0) {
		wcout << L"BAD JSON" << endl;
		return NULL;
	}


	if (data.get(L"type", L"nope").as<wstring>().compare(L"and") == 0) {
		Node* aNode = new Node;
		aNode->found = false;
		aNode->priority = 10;

		wjson children = data.get(L"children", L"nope");

		for (int j = 0; j < children.size(); ++j) {
			Node* retNode = parseNode(children[j], nodes);
			int id = nodes->size();
			retNode->index = id;
			aNode->children.push_back(retNode);
			nodes->push_back(retNode);
		}
		return aNode;
	}

	if (data.get(L"type", L"nope").as<wstring>().compare(L"or") == 0) {

		Node* oNode = new Node;
		oNode->found = false;
		oNode->priority = 11;

		wjson children = data.get(L"children", L"nope");

		for (int j = 0; j < children.size(); ++j) {
			Node* retNode = parseNode(children[j], nodes);
			int id = nodes->size();
			retNode->index = id;
			oNode->children.push_back(retNode);
			nodes->push_back(retNode);
		}
		return oNode;
	}


	if (type.compare(L"cert-dom") == 0) {
		Node* cert = new Node;
		cert->priority = 1;
		cert->dataId = CERT_DOMAIN_DATA;
		cert->found = false;
		cert->iocId = data.get(L"id", L"").as_int();
		wstring value = data.get(L"value", L"")[0].as<wstring>();

		cert->data = value;

		return cert;
	}

	if (type.compare(L"cert-ca") == 0) {
		Node* cert = new Node;
		cert->priority = 1;
		cert->dataId = CERT_ISSUER_DATA;
		cert->found = false;
		cert->iocId = data.get(L"id", L"").as_int();
		wstring value = data.get(L"value", L"")[0].as<wstring>();
		cert->data = value;

		return cert;
	}

	if (type.compare(L"network-ip") == 0) {
		Node* connect = new Node;
		connect->priority = 2;
		connect->dataId = CONNECTION_IP_DATA;
		connect->found = false;
		connect->iocId = data.get(L"id", L"").as_int();
		wstring value = data.get(L"value", L"")[0].as<wstring>();
		connect->data = value;

		return connect;
	}

	if (type.compare(L"network-name") == 0) {
		Node* connect = new Node;
		connect->priority = 2;
		connect->dataId = CONNECTION_DOMAIN_DATA;
		connect->found = false;
		connect->iocId = data.get(L"id", L"").as_int();
		wstring value = data.get(L"value", L"")[0].as<wstring>();
		connect->data = value;
		return connect;
	}

	if (type.compare(L"network-regex") == 0) {
		Node* connect = new Node;
		connect->priority = 2;
		connect->dataId = CONNECTION_DOMAIN_REGEX_DATA;
		connect->found = false;
		connect->iocId = data.get(L"id", L"").as_int();
		wstring value = data.get(L"value", L"")[0].as<wstring>();
		connect->data = value;
		return connect;
	}

	if (type.compare(L"dns") == 0) {
		Node* dns = new Node;
		dns->priority = 3;
		dns->found = false;
		dns->iocId = data.get(L"id", L"").as_int();
		wstring value = data.get(L"value", L"")[0].as<wstring>();
		dns->data = value;

		return dns;
	}

	if (type.compare(L"file") == 0) {

		FileNode* file = new  FileNode;
		file->dataId = FILE_EXACT_DATA;
		file->priority = 9;
		wjson values = data.get(L"value", L"");

		file->path = values[0].as<wstring>();
		file->name = values[1].as<wstring>();
		file->hash = values[3].as<wstring>();

		wstring hashType = values[2].as<wstring>();
		transform(hashType.begin(), hashType.end(), hashType.begin(), ::towlower);
		if (hashType.compare(L"sha256") == 0) {
			file->hashType = FILE_HASH_SHA256_DATA;
		}

		if (hashType.compare(L"md5") == 0) {
			file->hashType = FILE_HASH_MD5_DATA;
		}

		if (hashType.compare(L"sha1") == 0) {
			file->hashType = FILE_HASH_SHA1_DATA;
		}

		file->found = false;
		file->iocId = data.get(L"id", L"").as_int();

		return file;
	}

	if (type.compare(L"file-regex") == 0) {

		FileNode* file = new  FileNode;
		file->dataId = FILE_REGEX_DATA;
		file->priority = 9;
		wjson values = data.get(L"value", L"");

		file->path = values[0].as<wstring>();
		file->name = L"";
		file->hash = values[2].as<wstring>();

		wstring hashType = values[1].as<wstring>();
		transform(hashType.begin(), hashType.end(), hashType.begin(), ::towlower);
		if (hashType.compare(L"sha256") == 0) {
			file->hashType = FILE_HASH_SHA256_DATA;
		}

		if (hashType.compare(L"md5") == 0) {
			file->hashType = FILE_HASH_MD5_DATA;
		}

		if (hashType.compare(L"sha1") == 0) {
			file->hashType = FILE_HASH_SHA1_DATA;
		}

		file->found = false;
		file->iocId = data.get(L"id", L"").as_int();

		return file;
	}


	if (type.compare(L"mutex-name") == 0) {
		Node* mutex = new Node;
		mutex->priority = 4;
		mutex->found = false;
		mutex->iocId = data.get(L"id", L"").as_int();
		wstring value = data.get(L"value", L"")[0].as<wstring>();
		mutex->data = value;

		return mutex;
	}

	if (type.compare(L"process-hash") == 0) {
		Node* process = new Node;
		process->priority = 5;
		wjson values = data.get(L"value", L"");
		wstring hashType(values[0].as<wstring>());
		transform(hashType.begin(), hashType.end(), hashType.begin(), ::towlower);
		if (hashType.compare(L"sha256") == 0) {
			process->dataId = PROCESS_HASH_SHA256_DATA;
		}

		if (hashType.compare(L"md5") == 0) {
			process->dataId = PROCESS_HASH_MD5_DATA;
		}

		if (hashType.compare(L"sha1") == 0) {
			process->dataId = PROCESS_HASH_SHA1_DATA;
		}

		process->found = false;
		process->iocId = data.get(L"id", L"").as_int();
		wstring value = data.get(L"value", L"")[1].as<wstring>();
		process->data = value;

		return process;
	}

	if (type.compare(L"process-name") == 0) {
		Node* process = new Node;
		process->priority = 5;
		process->dataId = PROCESS_NAME_DATA;
		process->found = false;
		process->iocId = data.get(L"id", L"").as_int();
		wstring value = data.get(L"value", L"")[0].as<wstring>();
		process->data = value;

		return process;
	}

	if (type.compare(L"process-regex") == 0) {
		Node* process = new Node;
		process->priority = 5;
		process->dataId = PROCESS_REGEX_DATA;
		process->found = false;
		process->iocId = data.get(L"id", L"").as_int();
		wstring value = data.get(L"value", L"")[0].as<wstring>();
		process->data = value;
		return process;
	}

	if (type.compare(L"registry") == 0) {

		RegistryNode* regNode = new RegistryNode;
		regNode->priority = 8;
		regNode->dataId = REGISTRY_EXACT_DATA;
		regNode->found = false;
		regNode->iocId = data.get(L"id", L"").as_int();
		wstring value = data.get(L"value", L"")[0].as<wstring>();
		regNode->name = value;
		value = data.get(L"value", L"")[1].as<wstring>();
		regNode->valueName = value;

		regNode->valueValue = data.get(L"value", L"")[2].as<wstring>();
		return regNode;
	}

	if (type.compare(L"registry-regex") == 0) {
		RegistryNode* regNode = new RegistryNode;
		regNode->priority = 8;
		regNode->dataId = REGISTRY_REGEX_DATA;
		regNode->found = false;
		regNode->iocId = data.get(L"id", L"").as_int();
		wstring value = data.get(L"value", L"")[0].as<wstring>();
		regNode->name = value;
		value = data.get(L"value", L"")[1].as<wstring>();
		regNode->valueName = value;

		regNode->valueValue = data.get(L"value", L"")[2].as<wstring>();
		return regNode;
	}

	wcout << L"ERRROR";
	return new Node;


}