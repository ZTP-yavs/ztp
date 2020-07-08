//
// Created by aeryz on 12/7/19.
//

#ifndef ZTP_SSH_CLIENT_H
#define ZTP_SSH_CLIENT_H

#include "data_types.h"

namespace SSHClient
{
    /// Checks if login is possible via SSH.
    /// If so, save the session.
    bool start_session(unsigned int port, const std::string& ip, const Credentials& cred);

    // Execute remote command via SSH and return the output.
    std::string exec_cmd(const std::string& cmd);

    /// Free the ssh session
    void free_session();
}

#endif //ZTP_SSH_CLIENT_H
