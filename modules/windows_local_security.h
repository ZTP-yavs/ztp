#ifndef ZTP_MODULES_HEADERS_WINDOWS_LOCALSECURITY_HPP
#define ZTP_MODULES_HEADERS_WINDOWS_LOCALSECURITY_HPP

#include "../src/config.h"
#include "../src/data_types.h"
#include "../src/database_ctrl.h"

namespace WindowsLocalSecurity {    
    void Run(OSInfo &os, bsoncxx::types::b_oid target_id, const DatabaseCtrl &db, std::string root_path);
}


#endif