#ifndef ZTP_MODULES_HEADERS_EXTERNAL_MODULES_HPP
#define ZTP_MODULES_HEADERS_EXTERNAL_MODULES_HPP

#include <Python.h>
#include <iostream>
#include <vector>

namespace ExternalModules
{
    int call_external_modules(std::vector<std::string> &args, std::string filename); 
}

#endif