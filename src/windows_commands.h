#ifndef ZTP_WINDOWS_H
#define ZTP_WINDOWS_H

#include <iostream>
#include <vector>

namespace Windows{
    enum class RegistryType{
        REG_BINARY,
        REG_DWORD,
        REG_DWORD_LITTLE_ENDIAN,
        REG_DWORD_BIG_ENDIAN,
        REG_EXPAND_SZ,
        REG_LINK,
        REG_MULTI_SZ,
        REG_NONE,
        REG_QWORD,
        REG_QWORD_LITTLE_ENDIAN,
        REG_SZ,
        REG_ANY,
        REG_UNKNOWN
    };


    std::string reg_type_to_str(RegistryType reg_type);
    RegistryType reg_str_to_type(const std::string &str);

    struct Registry {
        std::string name;
        RegistryType reg_type;
        std::string data;

        std::string to_string(){
            return "Name: " + name + "\nType: " + reg_type_to_str(reg_type) + "\nData: " + data;
        }
    };
    std::string get_file_version(const std::string &path);

    Registry get_registry(const std::string &path,
                          const std::string &name,
                          RegistryType reg_type = RegistryType::REG_ANY);

    std::vector<std::string> get_registry_sub_keys(const std::string &path);

    bool registry_exists(const char *path);
}


#endif