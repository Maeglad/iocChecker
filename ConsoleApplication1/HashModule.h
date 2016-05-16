#pragma once

#ifndef HASHMODULE_H
#define HASHMODULE_H

#include <string>

class HashModule {
public:
	HashModule();
	~HashModule();

	int calc_md5A(std::string path, std::string *output);
	int calc_sha256A(std::string path, std::string *output);

	int calc_md5W(std::wstring path, std::wstring *output);
	int calc_sha256W(std::wstring path, std::wstring *output);

	int calc_sha1W(std::wstring path, std::wstring *output);
private:
	void hashToStringA(unsigned char* hash, int length, std::string* output);
	void hashToStringW(unsigned char* hash, int length, std::wstring* output);
};

#endif /* HASHMODULE_H */