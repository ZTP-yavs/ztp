
#include <iostream>
#include "alive_test.h"
#include "helper.h"
#include "vendor/easylogging++/easylogging++.h"

//#define NMAP_CMD "nmap --unprivileged -vv "
//#define NMAP_FIREWAL_CMD "sudo nmap -sS -T4 "

// Key to determine if host is up
#define UP_KEY "Host is up"

bool AliveTest::run(const std::string& ip, std::string nmap_option)
{
    std::string output;

    try {
        output = Helper::execute_shell_cmd(nmap_option + " " + ip);
    }
    catch (std::runtime_error& e) {
        LOG(ERROR) << e.what();
        return false;
    }

    if (output.find("command not found") != std::string::npos) {
        std::cerr << "'nmap' is needed to scan the target." << std::endl;
        exit(EXIT_FAILURE);
    }

    return output.find(UP_KEY) != std::string::npos;
}