//
// Created by aeryz on 12/7/19.
//

#ifndef ZTP_VERSION_OPS_H
#define ZTP_VERSION_OPS_H

#include <iostream>

namespace VersionOps
{
    void normalize(std::string& version);
    int compare(const std::string &lhs, const std::string &rhs);
}

#endif //ZTP_VERSION_OPS_H
