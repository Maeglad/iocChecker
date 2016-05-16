#include "stdafx.h"
#include "Node.h"

bool Node::evaluate() {

	if (priority < 10) return found;
	if (priority == 10) {

		for (int i = 0; i < children.size(); ++i) {
			if (children[i]->evaluate() == false) return false;
		}
		return true;
	}
	if (priority == 11) {


		for (int i = 0; i < children.size(); ++i) {

			if (children[i]->evaluate()) return true;
		}
		return false;
	}
}
