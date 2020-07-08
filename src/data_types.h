//
// Created by aeryz on 12/7/19.
//

#ifndef ZTP_DATA_TYPES_H
#define ZTP_DATA_TYPES_H

#include <iostream>
#include <vector>
#include <unordered_map>

#include <bsoncxx/oid.hpp>

#define DEFAULT_NMAP_OPTION "nmap --unprivileged -vv "
#define DEFAULT_SSH_PORT 22

struct Credentials
{
    std::string username;
    std::string password;
    std::string public_key_path;
};

struct OSInfo
{
    std::string os;
    std::string name;
    std::string version;
    std::unordered_map<std::string, std::string> fmt_packages;
    std::unordered_map<std::string, std::string> org_packages;
};

namespace ScanStatus
{
    enum e
    {
        FAILED = -1,
        NOT_STARTED,
        ONGOING,
        STOPPED,
        FINISHED
    };
}

struct Parameters
{
    std::vector<std::string> excluding_functions;
    std::string nmap_option;
    std::string ssh_username;
    std::string ssh_password;
    std::string public_key_path;
    std::string brute_force_path;
    std::string brute_force_type;
    int ssh_port;
    std::vector<std::string> targets;

    Parameters(std::string ssh_username)
            : ssh_username(std::move(ssh_username)),
              ssh_password(""),
              nmap_option(DEFAULT_NMAP_OPTION),
              public_key_path("/"),
              brute_force_path("/"),
              brute_force_type("light"),
              ssh_port(DEFAULT_SSH_PORT){}
};

#endif //ZTP_DATA_TYPES_H
