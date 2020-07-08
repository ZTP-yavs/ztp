//
// Created by aeryz on 12/7/19.
//

#ifndef ZTP_CONFIG_H
#define ZTP_CONFIG_H

#include <iostream>
#include <unordered_map>
#include <vector>

#define ZTP_CONFIG_PATH "/etc/ztp/ztp.conf"

class Config
{
private:
    struct Element
    {
        std::string category;
        std::unordered_map<std::string, std::string> kv;
    };

    std::vector<Element> m_elems;


public:
    /// Get - Get corresponding
    std::string get(const std::string &category, const std::string &key);
    void add(const std::string &category, const std::string &key, const std::string &value);

    void parse();
};

#endif //ZTP_CONFIG_H
