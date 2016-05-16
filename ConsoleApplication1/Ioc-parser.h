#pragma once

#ifndef IOC_PARSER_H
#define IOC_PARSER_H

#include "Node.h"
#include "jsoncons/json.hpp"

#define CERT_DOMAIN_DATA 1
#define CERT_ISSUER_DATA 2

#define CONNECTION_IP_DATA 1
#define CONNECTION_DOMAIN_DATA 2
#define CONNECTION_DOMAIN_REGEX_DATA 3

#define FILE_EXACT_DATA 0
#define FILE_REGEX_DATA 1
#define FILE_HASH_MD5_DATA 2
#define FILE_HASH_SHA256_DATA 3
#define FILE_HASH_SHA1_DATA 4

#define PROCESS_NAME_DATA 0
#define PROCESS_REGEX_DATA 1
#define PROCESS_HASH_SHA256_DATA 2
#define PROCESS_HASH_MD5_DATA 3
#define PROCESS_HASH_SHA1_DATA 4

#define REGISTRY_EXACT_DATA 1
#define REGISTRY_NAME_DATA 2
#define REGISTRY_REGEX_DATA 3

class IocParser {
public:
	std::vector<Node*> parseFile(std::string filePath);

private:

	Node* parseNode(jsoncons::wjson data, std::vector<Node*>* nodes);
};

#endif /* IOC_PARSER_H */

