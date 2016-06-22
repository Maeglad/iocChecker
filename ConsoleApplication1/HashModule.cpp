#include "stdafx.h"
#include "HashModule.h"

#include <string>
#include <cstdio>
#include <wchar.h>
#include <iostream>

#include <openssl/sha.h>
#include <openssl/md5.h>

HashModule::HashModule() {

};

HashModule::~HashModule() {

};

int HashModule::calc_md5A(std::string path, std::string* output) {
	unsigned char hash[MD5_DIGEST_LENGTH];
	FILE *file = fopen(path.c_str(), "rb");
	MD5_CTX md5;

	if (file == NULL) {
		output->clear();
		return 1;
	}

	MD5_Init(&md5);

	unsigned char* buffer = new unsigned char[10000];
	int count = 0;
	while ((count = fread(buffer, 1, 10000, file)) != 0) {
		MD5_Update(&md5, buffer, count);
	}

	MD5_Final(hash, &md5);
	hashToStringA(hash, MD5_DIGEST_LENGTH, output);

	fclose(file);
	delete buffer;
	return 0;
}

int HashModule::calc_md5W(std::wstring path, std::wstring* output) {
	unsigned char hash[MD5_DIGEST_LENGTH];
	FILE* file = _wfopen(path.c_str(), L"rb");
	MD5_CTX md5;

	if (file == NULL) {
		output->clear();
		return 1;
	}

	MD5_Init(&md5);

	unsigned char* buffer = new unsigned char[10000];
	int count = 0;
	while ((count = fread(buffer, 1, 10000, file)) != 0) {
		MD5_Update(&md5, buffer, count);
	}

	MD5_Final(hash, &md5);
	hashToStringW(hash, MD5_DIGEST_LENGTH, output);

	fclose(file);
	delete buffer;
	return 0;
}

int HashModule::calc_sha256A(std::string path, std::string* output) {
	unsigned char hash[SHA256_DIGEST_LENGTH];
	FILE* file = fopen(path.c_str(), "rb");

	SHA256_CTX sha256;
	if (file == NULL) {
		output->clear();
		return 1;
	}
	SHA256_Init(&sha256);

	unsigned char* buffer = new unsigned char[10000];
	int count = 0;
	while ((count = fread(buffer, 1, 10000, file))) {
		SHA256_Update(&sha256, buffer, count);
	}

	SHA256_Final(hash, &sha256);
	hashToStringA(hash, SHA256_DIGEST_LENGTH, output);

	fclose(file);
	delete buffer;
	return 0;
}

int HashModule::calc_sha256W(std::wstring path, std::wstring* output) {
	unsigned char hash[SHA256_DIGEST_LENGTH];
	FILE* file = _wfopen(path.c_str(), L"rb");

	SHA256_CTX sha256;
	if (file == NULL) {
		output->clear();
		return 1;
	}
	SHA256_Init(&sha256);

	unsigned char* buffer = new unsigned char[10000];
	int count = 0;
	while ((count = fread(buffer, 1, 10000, file))) {
		SHA256_Update(&sha256, buffer, count);
	}

	SHA256_Final(hash, &sha256);
	hashToStringW(hash, SHA256_DIGEST_LENGTH, output);

	fclose(file);
	delete buffer;
	return 0;
}

int HashModule::calc_sha1W(std::wstring path, std::wstring* output) {
	unsigned char hash[SHA_DIGEST_LENGTH];
	FILE* file = _wfopen(path.c_str(), L"rb");

	SHA_CTX sha1;
	if (file == NULL) {
		output->clear();
		return 1;
	}
	SHA1_Init(&sha1);

	unsigned char* buffer = new unsigned char[10000];
	int count = 0;
	while ((count = fread(buffer, 1, 10000, file))) {
		SHA1_Update(&sha1, buffer, count);
	}

	SHA1_Final(hash, &sha1);
	
	hashToStringW(hash, SHA_DIGEST_LENGTH, output);

	fclose(file);
	delete buffer;
	return 0;
}

void HashModule::hashToStringA(unsigned char* hash, int length, std::string* output) {
	char* buffer = new char[(length * 2) + 1];
	output->clear();

	for (int i = 0; i < length; ++i) {
		sprintf(buffer + (i * 2), "%02x", hash[i]);
	}

	buffer[length * 2] = '\0';
	output->append(buffer);
	delete buffer;
}



void HashModule::hashToStringW(unsigned char* hash, int length, std::wstring* output) {
	wchar_t* buffer = new wchar_t[(length * 2) + 1];
	output->clear();

	for (int i = 0; i < length; ++i) {
		swprintf(buffer + (i * 2), L"%02x", hash[i]);
	}

	buffer[length * 2] = '\0';
	output->append(buffer);
	delete buffer;
}