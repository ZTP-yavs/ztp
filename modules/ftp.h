//
// Created by aeryz on 4/25/20.
//

#ifndef ZTP_FTP_H
#define ZTP_FTP_H

#include <string>
#include <vector>
#include "../src/vendor/rapidjson/document.h"
#include "../src/database_ctrl.h"
#include <bsoncxx/oid.hpp>

namespace FTP {
    struct Credentials {
        std::string username;
        std::string password;
    };

    bool login(std::vector<std::string> excluding_functions, Credentials credentials, std::string ip_address);

    //std::vector<int> login(std::vector<Credentials> credentials_list);

    void ftp_login_call(std::vector<std::string> excluding_functions, std::vector<std::string> ip_addresses, const DatabaseCtrl &db, const bsoncxx::types::b_oid target_id);
}

#endif //FTP_FTP_H
