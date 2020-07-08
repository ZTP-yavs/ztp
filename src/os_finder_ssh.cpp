#include "os_finder_ssh.h"
#include "ssh_client.h"
#include "vendor/easylogging++/easylogging++.h"
#include "version_ops.h"

#include <regex>
#include <unordered_map>
#include <unistd.h>

/*
 * TODO | OS tests should throw in a situation like for example if "debian" is identified but os version is not identified
 * TODO | nor supported, it should throw and os test should halt.
 */

using bsoncxx::builder::stream::document;
using bsoncxx::builder::stream::finalize;

bool OSFinderSSH::test_debian(OSInfo& os_info)
{
    std::string output;
    try {
        output = SSHClient::exec_cmd("cat /etc/debian_version");
    }
    catch (std::runtime_error& e) {
        LOG(ERROR) << e.what();
        return false;
    }

    std::regex rx(R"(([0-9]+)\.[0-9][^ ]*)");
    std::smatch match;

    if (std::regex_match(output, match, rx)) {
        const std::string version = match[1];
        int version_int;
        try {
            version_int = std::stoi(version);
        }
        catch (const std::exception &e) {
            LOG(ERROR) << "Error while converting version to int: " << e.what();
            return false;
        }

        if (version_int < 3 || version_int > 10)
            return false;

        os_info.version = "Deb" + version;
        os_info.name    = "debian";
        get_packages_dpkg(os_info);
        return true;
    }
    return false;
}


bool OSFinderSSH::is_linux(OSInfo &os_info){
    std::string output;
    try {
        output = SSHClient::exec_cmd("uname -r");
    }
    catch (std::runtime_error& e) {
        LOG(ERROR) << e.what();
        return false;
    }

    if(output.length() > 0){
        os_info.os = "linux";
        return true;
    }
    return false;
}

bool OSFinderSSH::test_systeminfo_method(OSInfo &os_info){ //systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

    std::string output;
    try {
        output = SSHClient::exec_cmd("systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version");
    }
    catch (std::runtime_error& e) {
        LOG(ERROR) << e.what();
        return false;
    }
    std::stringstream ss(output);
    std::string token;
    std::regex rx(R"(((.*): *(.*)))");
    std::smatch match;
    std::string name;
    std::string ver;
    while (std::getline(ss, token))
	{
        token.erase(token.length() -1); //last character of token is "\r", we should remove it.
		if (std::regex_match(token, match, rx))
		{
            if(match[2] == "OS Name")
                os_info.name = match[3];
            else if(match[2] == "OS Version")
                os_info.version = match[3];
        }
	}
    os_info.os = "windows";
    return true;
}

bool OSFinderSSH::test_lsb_method(OSInfo &os_info)
{
    std::string output;
    try {
        output = SSHClient::exec_cmd("lsb_release -a -s");
    }
    catch (std::runtime_error& e) {
        LOG(ERROR) << e.what();
        return false;
    }

    //lsb_release -a -s returns =>
    //on arch based:
        //n/a ManjaroLinux "Manjaro Linux" 18.1.5 Juhreya
    
    //on debian based:
        //No LSB modules are available.
        //Ubuntu
        //Pop!_OS 19.04
        //19.04
        //disco

    std::vector<std::string> output_array;
    output_array.reserve(4);   // 4 lines may come from lsb_release, preventing copy

    std::stringstream ss(output);
    std::string token;

    // TODO: Maybe multi-line regex instead of line by line parsing
    while (std::getline(ss, token))
        output_array.emplace_back(token);
    
    if (output_array.size() == 4) {
        if(output_array[0] == "Ubuntu" || output_array[0] == "Pop") {
        os_info.name = "ubuntu";
        os_info.version = "Ubuntu" + output_array[2];
        if (output_array[1].find(" LTS") != std::string::npos)
            os_info.version += " LTS";
        get_packages_dpkg(os_info);
        return true;
        }
        else if(output_array[0] == "Pardus") { // Since Pardus is Debian based
            os_info.name = "debian";
            os_info.version = "Deb";

            int os_version = 0;
            if (output_array[2] == "17.5") {
                os_version = 9;
                os_info.version += "9";
            }
            else {
                LOG(WARNING) << "Pardus is identified but version is not: " << output_array[2];
                return false;
            }

            if(os_version < 3 || os_version > 10) {
                LOG(WARNING) << "Unsupported debian version.";
                return false;
            }
            get_packages_dpkg(os_info);
            return true;
        }
    }
    else if(output_array.size() == 1){
        std::regex rx("([A-Za-z0-9$&+,:;=?@#|'<>.^*()%!-]([^ ]+)?)");

        std::sregex_iterator currentMatch(output_array[0].begin(), output_array[0].end(), rx);

        *currentMatch++;
        std::smatch distributorID = *currentMatch;

        std::stringstream iss (output_array[0]);
        
        if(distributorID.str() == "ManjaroLinux"){
            os_info.name = "arch";
            os_info.version = "Arch";
            get_packages_pacman(os_info);
            return true;
        }
        return false;
    }
    /*
    else{
        LOG(DEBUG) << "Failed to parse LSB command: " << output;
        return false;
    }
    */
    LOG(DEBUG) << "TestLSBMethod failed: " << output;
    return false;
}


bool OSFinderSSH::run(OSInfo &os_info, const DatabaseCtrl &db, const bsoncxx::types::b_oid& target_id)
{
    if(is_linux(os_info)){
        if (test_lsb_method(os_info) || test_debian(os_info)) {
            db.insert_one("dynamicreport", document{}
                    << "dynamic_report" << "OS Detected\n\tName: " + os_info.name + "\n\tVersion: " + os_info.version
                    << "static_report"  << ""
                    << "target"        << target_id
                    << finalize);
            return true;
        }
    }
    else{
        /*
        systeminfo | findstr /B /C:"OS Name" /C:"OS Version" => 

        OS Name:                   Microsoft Windows 10 Home
        OS Version:                10.0.18363 N/A Build 18363
        */
       if(test_systeminfo_method(os_info)){
            db.insert_one("dynamicreport", document{}
                    << "dynamic_report" << "OS Detected\n\tName: " + os_info.name + "\n\tVersion: " + os_info.version
                    << "static_report"  << ""
                    << "target"        << target_id
                    << finalize);
            return true;
       }

    }
        
    db.insert_one("dynamicreport", document{}
                    << "dynamic_report" << "OS Detection Failed"
                    << "static_report"  << ""
                    << "target"        << target_id
                    << finalize);
    return false;
}


void OSFinderSSH::get_packages_dpkg(OSInfo &os_info)
{
    std::string packages_str;
    try {
        packages_str = SSHClient::exec_cmd("dpkg -l");
    }
    catch (std::runtime_error& e) {
        LOG(ERROR) << e.what();
        return;
    }

    std::stringstream packages_ss(packages_str);
    std::string line;
    std::regex rx(R"(ii +([^ :]+)([^ ]*) +([^ ]+).*)");
    std::smatch match;

    while (std::getline(packages_ss, line)) {
        if (std::regex_match(line, match, rx))
        {
            // TODO: Normalizing must be done in the ZTD-GENERATOR
            std::string version = match[3];
            os_info.org_packages[match[1]] = version;
            VersionOps::normalize(version);
            os_info.fmt_packages[match[1]] = version;
        }
    }
}

void OSFinderSSH::get_packages_pacman(OSInfo &os_info){

    std::string packages_str;
    try {
        packages_str = SSHClient::exec_cmd("pacman -Q");
    }
    catch (std::runtime_error& e) {
        LOG(ERROR) << e.what();
        return;
    }

    std::stringstream packages_ss(packages_str);
    std::string line;
    std::regex rx("([A-Za-z0-9$&+,:;=?@#|'<>.^*()%!-]([^ ]+)?)");
    
    while ( std::getline(packages_ss, line) ){

        std::sregex_iterator currentMatch(line.begin(), line.end(), rx);

        std::smatch name = *currentMatch;
        currentMatch++;
        std::smatch versionMatch = *currentMatch;
        std::string version = versionMatch.str();
            
        os_info.org_packages[name.str()] = version;
        VersionOps::normalize(version);
        os_info.fmt_packages[name.str()] = version;
    }
}
