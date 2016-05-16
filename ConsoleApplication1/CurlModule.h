#pragma once

#ifndef CURLMODULE_H
#define CURLMODULE_H

#include <string>
#include <stdio.h>
#include "jsoncons/json.hpp"
class CurlModule {
public:
	int fetchDataFromServer(std::string url, std::string setName);
	int uploadDataToServer(std::string url, std::string setName);

private:
	static size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream);
};

#endif /* CURLMODULE_H */
