#ifndef OCI_DECORATOR_H
#define OCI_DECORATOR_H

#include <vector>
#include <string>

enum inventory {
        devices       = 0,
        binaries      = 1,
        libraries     = 2,
        directories   = 3,
        miscellaneous = 4,
        group_entries = 5
};

using namespace std;

struct oci_config_ {
	string version;
	string log_level;
	string activation_flag;
	vector<string> driver_feature;
	vector<vector<vector<string>>> inventory;
};


#endif /* OCI_DECORATOR_H */
