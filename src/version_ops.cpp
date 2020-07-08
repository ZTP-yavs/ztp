#include "version_ops.h"
#include <regex>
#include <string>

void VersionOps::normalize(std::string& version)
{
    if ( version.empty() )
        return;

    std::regex rx_lenny(R"([+-.]lenny)");
    std::regex rx_squeeze(R"([+-.]squeeze)");
    std::regex rx_wheezy(R"([+-.]wheezy)");
    std::regex rx_dot(R"(([0-9])([A-Za-z]))");
    std::regex rx(R"(^([0-9]:)?(.*)$)");

    version = std::regex_replace(version, rx_lenny, "lenny");
    version = std::regex_replace(version, rx_squeeze, "squeeze");
    version = std::regex_replace(version, rx_wheezy, "wheezy");
    version = std::regex_replace(version, rx_dot, "$1.$2");

    std::smatch match;
    if ( !std::regex_match(version, match, rx) )
        return;

    version = match[2];
}

int VersionOps::compare(const std::string &lhs, const std::string &rhs)
{
    if ( lhs == rhs )
        return 0;

    int len_a = lhs.size();
    int len_b = rhs.size();

    std::regex number_rx(R"(([0-9]+)[^]*)");

    std::string t_lhs = lhs;
    std::string t_rhs = rhs;

    if ( len_a == 0 )
        if ( len_b > 0 )
            return -1;
        else
            return 0;

    for ( int i = 0; i < len_a; i++ )
    {
        if ( i >= len_b )
            return 1;

        if ( isdigit(lhs[i]) && isdigit(rhs[i]) )
        {
            std::smatch match_lhs;
            std::smatch match_rhs;

            std::string lhs_substr = lhs.substr(i);
            std::string rhs_substr = rhs.substr(i);

            std::regex_match(lhs_substr, match_lhs, number_rx);
            std::regex_match(rhs_substr, match_rhs, number_rx);

            std::string sub_lhs = match_lhs[1];
            std::string sub_rhs = match_rhs[1];

            t_lhs = lhs.substr(i + sub_lhs.size());
            t_rhs = rhs.substr(i + sub_rhs.size());

            int i_sub_lhs = atoi(sub_lhs.c_str());
            int i_sub_rhs = atoi(sub_rhs.c_str());

            if ( i_sub_lhs > i_sub_rhs )
                return 1;
            else if ( i_sub_lhs < i_sub_rhs )
                return -1;
            else
            if ( t_lhs.empty() || t_rhs.empty() )
                if ( t_lhs.empty() )
                    if ( t_rhs.empty() )
                        return 0;
                    else
                        return -1;
                else
                    return 1;
            if ( t_lhs[0] == '.' && t_rhs[0] != '.' )
                return 1;
            if ( t_lhs[0] != '.' && t_rhs[0] == '.' )
                return -1;
        }

        if ( lhs[i] < rhs[i] )
            return -1;
        else if ( lhs[i] > rhs[i] )
            return 1;
        if ( i == len_a - 1 && len_b > len_a )
            return -1;
    }
    return 0;
}