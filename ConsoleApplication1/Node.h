#pragma once

#ifndef NODE_H
#define NODE_H

#include <string>
#include <vector>
#include <iostream>
class Node {
public:
	int iocId, index;
	bool found;
	int priority;
	int dataId;
	std::wstring data;
	std::wstring name;
	std::vector<Node*> children;
	bool evaluate();
	std::vector<std::wstring> fdata;
};


class RegistryNode : public Node {
public:

	std::wstring name; // ak je exact true obsahuje path napr. HKEY_CURRENT_USER\\subkey1\\subsubkey2\\ ...\\desiredkey
					   // inak obsahuje nazov key -> keyname
	std::wstring valueName; // nazov hodnoty, ak je noValue = true ignoruje sa

	std::wstring valueValue; // hodnota hodnoty, ak je noValue = true ignoruje sa 
							 //int dataLengt
	bool noValue;
};

class FileNode : public Node {
public:
	std::wstring path;
	std::wstring name;
	std::wstring hash;
	int hashType;
};

#endif /* NODE_H */

