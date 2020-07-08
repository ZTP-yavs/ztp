#include "config.h"

#include <fstream>
#include <regex>

#include "vendor/easylogging++/easylogging++.h"

void Config::parse()
{
    std::ifstream infile(ZTP_CONFIG_PATH);

    // TODO: Default values may be specified and used in this situation instead of exiting.
    if (!infile)
        LOG(FATAL) << "Configuration file does not exist. ( " << ZTP_CONFIG_PATH << " )";

    // Regex: CATEGORY:KEY "VALUE"
    std::regex rx( R"( *([^:]+):([^ ]+) +\" *([^ ]+) *\" *)" );
    std::smatch match;
    std::string line;

    while (std::getline(infile, line)) {
        if (std::regex_match(line, match, rx) && match.size() == 4)
            add(match[1], match[2], match[3]);
    }

    infile.close();
}

std::string Config::get(const std::string& category, const std::string& key)
{
    for (auto elem: m_elems) {
        if (elem.category == category)
            return elem.kv[key];
    }
    return "";
}

void Config::add(const std::string& category, const std::string& key, const std::string& value)
{
    for (auto elem: m_elems) {
        if (elem.category == category) {
            elem.kv[key] = value;
            return;
        }
    }

    Element elem{category};
    elem.kv[key] = value;
    m_elems.push_back(elem);
}



