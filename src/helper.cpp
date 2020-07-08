//
// Created by aeryz on 12/7/19.
//

#include <experimental/filesystem>
#include <iostream>
#include <fstream>
#include "helper.h"

std::string Helper::execute_shell_cmd(const std::string& cmd)
{
    std::array<char, 128> buffer{};
    std::string result;

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("Couldn't execute command due to pipe error. (errno: " + std::to_string(errno) + ")");
    }

    while (fgets(buffer.data(), 128, pipe) != nullptr) {
        result += buffer.data();
    }

    return result;
}