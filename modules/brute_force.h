#ifndef ZTP_MODULES_HEADERS_BRUTEFORCE_HPP
#define ZTP_MODULES_HEADERS_BRUTEFORCE_HPP

#include "../src/config.h"
#include "../src/database_ctrl.h"
#include <bsoncxx/oid.hpp>

namespace BruteForce 
{    
    bool bruteForceRouter(std::string ip, std::string username, std::string password);
    void bruteForceCall(std::string bruteForceType, std::string brute_force_path, std::string ip, std::vector<std::string> excluding_functions, const DatabaseCtrl &db, bool already_checked, const bsoncxx::types::b_oid target_id);
}

#endif