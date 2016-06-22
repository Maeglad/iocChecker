#include "stdafx.h"
#include "CurlModule.h"


#include <cstdlib>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <codecvt>
#include <io.h>
#include <fcntl.h>
#include <tchar.h>
#include <locale>

size_t CurlModule::write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	size_t written = fwrite(ptr, size, nmemb, stream);
	return written;
}

int CurlModule::uploadDataToServer(std::string url, std::string setName) {
	CURL *curl;
	CURLcode res;
	std::ifstream dataIn;
	std::string path;
	path.append("./logs/");
	path.append(setName.begin(), setName.end());
	path.append(".log");
	dataIn.open(path.c_str(), std::wifstream::in);
	std::string test, ioc;

	while (dataIn.eof() == false) { 
		dataIn >> test; 
		ioc.append(test);
	}
	//std::cout << ioc;
	//return 0;
	
	//jsoncons::wjson root;
	//dataIn >> root;

	curl = curl_easy_init();
	if (curl) {
		//std::wstring data = root.as_string();
		//int size_needed = WideCharToMultiByte(CP_UTF8, 0, &data[0], (int)data.size(), NULL, 0, NULL, NULL);
		//std::string strTo(size_needed, 0);
		
		//WideCharToMultiByte(CP_UTF8, 0, &data[0], (int)data.size(), &strTo[0], size_needed, NULL, NULL);
		

		//strTo = curl_easy_escape(curl, strTo.c_str(), strTo.size());
		//std::cout << strTo << " " << size_needed;
		std::string connect, post;
		connect.append(url);
		post.append("controller=client&action=upload&report=");
		post.append(ioc);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post.c_str());
		//curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, size*4);
		curl_easy_setopt(curl, CURLOPT_URL, connect.c_str());     
		char buffer[CURL_ERROR_SIZE];

		curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, buffer);
		buffer[0] = 0;

	

		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

		curl_easy_setopt(curl, CURLOPT_CAINFO, "./cert/ca.pem");

		curl_easy_setopt(curl, CURLOPT_SSLCERT, "./cert/client.pem");

		curl_easy_setopt(curl, CURLOPT_SSLKEY, "./cert/client.key");

		curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
		curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
		
		res = curl_easy_perform(curl);
	//	delete data;
		if (res != CURLE_OK) {
			printf("%s", curl_easy_strerror(res));
			printf("\n%s", buffer);
		}
		
		curl_easy_cleanup(curl);

	}
	return 0;
}

int CurlModule::fetchDataFromServer(std::string url, std::string setName) {
	CURL *curl;
	CURLcode res;

	FILE *fp;



	curl = curl_easy_init();
	if (curl) {
		std::string s;
		s.append("./iocs/");
		s.append(setName);
		s.append(".txt");
		fp = fopen(s.c_str(), "w");

		std::string connect, post;
		connect.append(url);
		
		post.append("controller=client&action=request&name=");
		post.append(setName);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post.c_str());
		curl_easy_setopt(curl, CURLOPT_URL, connect.c_str());       
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

		char buffer[CURL_ERROR_SIZE];

		curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, buffer);
		buffer[0] = 0;


		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

		curl_easy_setopt(curl, CURLOPT_CAINFO, "./cert/ca.pem");

		curl_easy_setopt(curl, CURLOPT_SSLCERT, "./cert/client.pem");

		curl_easy_setopt(curl, CURLOPT_SSLKEY, "./cert/client.key");

		curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
		curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);

		res = CURLE_OK;
		res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			printf("%s", curl_easy_strerror(res));
			printf("\n%s", buffer);
		}
		fclose(fp);
		curl_easy_cleanup(curl);
	}
	return 0;
}
