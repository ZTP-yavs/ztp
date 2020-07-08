// Internal
#include "local_security.h"
#include "../src/version_ops.h"

// External local
#include "../src/vendor/easylogging++/easylogging++.h"
#include "../src/vendor/rapidjson/document.h"
#include "../src/vendor/rapidjson/filereadstream.h"

// Std
#include <iostream>
#include <experimental/filesystem>


namespace fs = std::experimental::filesystem;
using bsoncxx::builder::stream::document;
using bsoncxx::builder::stream::finalize;

void LocalSecurity::Run(OSInfo &os, bsoncxx::types::b_oid target_id, const DatabaseCtrl &db, std::string root_path, std::vector<std::string> excluding_functions)
{
    if(excluding_functions.size() != 0){
        for(std::string &func: excluding_functions){
            if(func == "linux_local_security")
                return;
        }
    }
    if (os.name.empty() || os.version.empty())
    {
        std::cerr << "OS name or version is empty. Aborting.." << std::endl;
        exit(EXIT_FAILURE);
    }

    if (root_path[root_path.size() -1] != '/')
        root_path.push_back('/');

    std::string dir_path = root_path + os.name + "/ztd";
    if ( !fs::exists(dir_path) || !fs::is_directory(dir_path) )
    {
        LOG(ERROR) << "Missing or corrupted directory: " << dir_path;
        exit(EXIT_FAILURE);
    }

    for (auto& file: fs::directory_iterator(dir_path))
    {
        if (file.path().extension() != ".json")
            continue;

        FILE* fp = fopen(file.path().c_str(), "r");

        // TODO: Static size
        char readBuffer[65536];
        rapidjson::FileReadStream is(fp, readBuffer, sizeof(readBuffer));
        rapidjson::Document doc;
        if (doc.ParseStream(is).HasParseError())
        {
                LOG(ERROR) << "Json format is invalid! Json name: " << file.path().c_str();
                goto close_n_cont;
        }

        if (!doc.HasMember("os") || !doc.HasMember("id")){
                LOG(ERROR) << "Json should have keys 'os' and 'id'! FatalError no id or os";
                goto close_n_cont;
        }

        for (rapidjson::SizeType i = 0; i < doc["os"].Size(); i++)
        {
            if (!doc["os"][i].HasMember("key") || !doc["os"][i].HasMember("packages")){
                LOG(ERROR) << "Json os should have key and packages key! FatalError oid: " << doc["id"].GetString();
                goto close_n_cont;
            }

            if(doc["os"][i]["key"].GetString() == os.version)
            {
                for(rapidjson::SizeType j = 0; j < doc["os"][i]["packages"].Size(); j++)
                {
                    if (!doc["os"][i]["packages"][j].HasMember("name") || !doc["os"][i]["packages"][j].HasMember("version")){
                        LOG(ERROR) << "Json os[i]['packages'] should have name and version key! Error oid: " << doc["id"].GetString();
                        continue;
                    }
                    if(!os.fmt_packages[doc["os"][i]["packages"][j]["name"].GetString()].empty())
                    {
                        std::string version = doc["os"][i]["packages"][j]["version"].GetString();
                        VersionOps::normalize(version); // TODO: Normalizing must be done in the ZTD-GENERATOR
                        if (VersionOps::compare(version,
                                                os.fmt_packages[doc["os"][i]["packages"][j]["name"].GetString()]) > 0)
                        {
                             std::string solution = "\nPackage: "+ std::string(doc["os"][i]["packages"][j]["name"].GetString()) +"\n\tInstalled version: "
                                                            + os.org_packages[doc["os"][i]["packages"][j]["name"].GetString()] + "\n\tFixed version: "
                                                            + doc["os"][i]["packages"][j]["version"].GetString();

                            db.insert_one("dynamicreport", document{}
                                    << "static_report" << doc["id"].GetString()
                                    << "dynamic_report" << solution.c_str()
                                    << "target" << target_id
                                    << finalize);
                        }
                        break;
                    }
                }
            }
        }
        close_n_cont:;
        fclose(fp);
     }
}
