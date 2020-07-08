#ifndef ZTP_MODULES_HEADERS_LOCALSECURITY_HPP
#define ZTP_MODULES_HEADERS_LOCALSECURITY_HPP

#include "../src/config.h"
#include "../src/data_types.h"
#include "../src/database_ctrl.h"

namespace LocalSecurity 
{    
    void Run(OSInfo &os, bsoncxx::types::b_oid target_id, const DatabaseCtrl &db, std::string root_path, std::vector<std::string> excluding_functions);
}

#endif