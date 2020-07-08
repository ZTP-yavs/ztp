#include <regex>
#include <vector>

#include "ssh_client.h"
#include "data_types.h"
#include <string>
#include <boost/algorithm/string/replace.hpp>

#include "windows_commands.h"

std::string Windows::get_file_version(const std::string &path){
    std::string cmd = "wmic datafile where name=\""+boost::replace_all_copy(path, "\\", "\\\\")+"\" get Version /value";
    std::string output = SSHClient::exec_cmd(cmd);
	
    std::stringstream ss(output);
	std::string token;
    std::regex rx(R"((.*)=(.*))");
	std::smatch match;
	while (std::getline(ss, token)){
        token.erase(token.end()-2, token.end()); //last 2 character of token is "\r", we should remove it.
		if (std::regex_match(token, match, rx)){
			return match[2]; 
		}
	}
    return "";
}

Windows::Registry Windows::get_registry(const std::string &path, const std::string &name,
								  Windows::RegistryType reg_type){
	std::string cmd = "reg query \"" + path + '"';
	if (reg_type != RegistryType::REG_ANY)
		cmd += " /T " + reg_type_to_str(reg_type);
	std::string output = SSHClient::exec_cmd(cmd);

	if (output.empty())
		return Registry{"", RegistryType::REG_ANY, ""};

    std::stringstream ss(output);
	std::string token;
    std::regex rx(R"( +([^ ]+) +([^ ]+) +(.+) *)");
	std::smatch match;
	
	while (std::getline(ss, token)){
        token.erase(token.length() -1); //last character of token is "\r", we should remove it.
		if (std::regex_match(token, match, rx))
			if (match[1] == name)
                return Registry{match[1], reg_str_to_type(std::string(match[2])), match[3]}; 
	}

	return Registry{"", RegistryType::REG_UNKNOWN, ""};
}

std::vector<std::string> Windows::get_registry_sub_keys(const std::string &path)
{
	std::string output = SSHClient::exec_cmd("reg query " + path);

	output.erase(
            std::remove_if(output.begin(), output.end(), [](char c){ return c == 13; }),
            output.end()
    );

	std::stringstream ss(output);
	std::string token;
	std::vector<std::string> vec;
	while (std::getline(ss, token)){
		if (token.find(path) != std::string::npos)
			vec.push_back(token);
	}
	return vec;
	
}

bool Windows::registry_exists(const char *path){
	return !SSHClient::exec_cmd("reg query " + std::string(path)).empty();
}

std::string Windows::reg_type_to_str(Windows::RegistryType reg_type){
	switch (reg_type){
		case RegistryType::REG_BINARY: 			    return "REG_BINARY";
		case RegistryType::REG_DWORD:  			    return "REG_DWORD";
		case RegistryType::REG_DWORD_LITTLE_ENDIAN: return "REG_DWORD_LITTLE_ENDIAN";
		case RegistryType::REG_DWORD_BIG_ENDIAN:    return "REG_DWORD_BIG_ENDIAN";
		case RegistryType::REG_EXPAND_SZ:           return "REG_EXPAND_SZ";
		case RegistryType::REG_LINK: 				return "REG_LINK";
		case RegistryType::REG_MULTI_SZ:			return "REG_MULTI_SZ";
		case RegistryType::REG_NONE:				return "REG_NONE";
		case RegistryType::REG_QWORD:				return "REG_QWORD";
		case RegistryType::REG_QWORD_LITTLE_ENDIAN: return "REG_QWORD_LITTLE_ENDIAN";
		case RegistryType::REG_SZ:				    return "REG_SZ";
		case RegistryType::REG_ANY:				    return "REG_ANY";
		default:			                        return "REG_UNKNOWN";
	}
	return "";
}

Windows::RegistryType Windows::reg_str_to_type(const std::string &str){
	if      (str == "REG_BINARY")              return RegistryType::REG_BINARY;
	else if (str == "REG_DWORD")               return RegistryType::REG_DWORD;
	else if (str == "REG_DWORD_LITTLE_ENDIAN") return RegistryType::REG_DWORD_LITTLE_ENDIAN;
	else if (str == "REG_DWORD_BIG_ENDIAN")    return RegistryType::REG_DWORD_BIG_ENDIAN;
	else if (str == "REG_EXPAND_SZ")           return RegistryType::REG_EXPAND_SZ;
	else if (str == "REG_LINK")                return RegistryType::REG_LINK;
	else if (str == "REG_MULTI_SZ")            return RegistryType::REG_MULTI_SZ;
	else if (str == "REG_NONE")                return RegistryType::REG_NONE;
	else if (str == "REG_QWORD")               return RegistryType::REG_QWORD;
	else if (str == "REG_QWORD_LITTLE_ENDIAN") return RegistryType::REG_QWORD_LITTLE_ENDIAN;
	else if (str == "REG_SZ")                  return RegistryType::REG_SZ;
	else if (str == "REG_ANY")                 return RegistryType::REG_ANY;

	return RegistryType::REG_UNKNOWN;
}