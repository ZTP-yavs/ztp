//
// Created by aeryz on 12/7/19.
//

#ifndef ZTP_OS_FINDER_SSH_H
#define ZTP_OS_FINDER_SSH_H

#include <iostream>
#include <vector>
#include "../src/data_types.h"
#include <unordered_map>
#include "../src/database_ctrl.h"

namespace OSFinderSSH
{
    bool run(OSInfo &os_info, const DatabaseCtrl &db, const bsoncxx::types::b_oid& target_id);
    bool test_debian(OSInfo& os_info);
    bool test_lsb_method(OSInfo& os_info);
    bool test_systeminfo_method(OSInfo& os_info);
    void get_packages_dpkg(OSInfo &os_info);
    void get_packages_pacman(OSInfo &os_info);
    bool is_linux(OSInfo &os_info);

}

#endif //ZTP_OS_FINDER_SSH_H
