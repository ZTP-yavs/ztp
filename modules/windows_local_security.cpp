// Internal
#include "windows_local_security.h"
#include "../src/version_ops.h"
#include "../src/database_ctrl.h"
#include "../src/windows_commands.h"
#include "../src/redis_namespace.h"
#include "../src/version_ops.h"

// External local
#include "../src/vendor/easylogging++/easylogging++.h"
#include "../src/vendor/rapidjson/document.h"
#include "../src/vendor/rapidjson/filereadstream.h"

// Std
#include <iostream>

#if defined(__cpp_lib_filesystem)
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

using namespace sw::redis;

using bsoncxx::builder::stream::document;
using bsoncxx::builder::stream::finalize;

bool file_control(const bsoncxx::types::b_oid& target_id, 
                  const DatabaseCtrl &db,
                  const std::string& hash, 
                  const rapidjson::Document& doc,
                  const std::string& file_base)
{

    std::string file_name = doc["file"]["name"].GetString();

    //RadisLayer::redis
    std::vector<OptionalString> vals;
    RedisLayer::redis.hmget(hash, {"FILE_VER/" + file_name}, std::back_inserter(vals));
    std::string ver;
    if(vals[0].has_value())
    {
        std::cout << "File pulled from cache" << vals[0].value() << '\n';
        ver = vals[0].value();
    }
    else{
        std::cout << "Caching file\n";
        ver = Windows::get_file_version(file_base + doc["file"]["path"].GetString() + file_name);
        if (ver.empty())
            return false;
        RedisLayer::redis.hset(hash, "FILE_VER/" + file_name, ver);
    }

    std::string min_ver = doc["file"]["version"]["min"].GetString();
    std::string max_ver = doc["file"]["version"]["max"].GetString();


    if (VersionOps::compare(ver, min_ver) >= 0 && 
        VersionOps::compare(ver, max_ver) < 0)
    {
        LOG(DEBUG) << "Vulnerable";
        db.insert_one( "dynamicreport", document{}
                    << "static_report" << doc["id"].GetString()
                    << "dynamic_report" << "Installed version: " + ver + "\nFixed version: " + max_ver 
                    << "target" << target_id
                    << finalize);
    }

    return true;
}

void WindowsLocalSecurity::Run(OSInfo &os, bsoncxx::types::b_oid target_id, const DatabaseCtrl &db, std::string root_path){
    if (os.name.empty() || os.version.empty()){
        std::cerr << "OS name or version is empty. Aborting windows local security checks." << std::endl;
        return;
    }

    if (root_path[root_path.size() - 1] != '/')
        root_path.push_back('/');

    std::string dir_path = root_path + os.os;

    if ( !fs::exists(dir_path) || !fs::is_directory(dir_path) ){
        LOG(ERROR) << "Missing or corrupted directory: " << dir_path;
        return;
    }

    const auto target = db.find_one("target", document{}
        << "_id" << target_id
        << finalize);

    if (!target)
    {
        LOG(FATAL) << "Couldn't find the target in the database.";
    }

    std::string hash;
    {
        std::string scan_hash = (*target).view()["scan_hash"].get_oid().value.to_string();
        std::string ip = (*target).view()["ip"].get_utf8().value.to_string();
        hash = scan_hash + "|" + ip;
    }

    for (auto& file: fs::directory_iterator(dir_path)){
        if (file.path().extension() != ".json")
            continue;

        FILE* fp = fopen(file.path().c_str(), "r");

        // TODO: Static size
        char readBuffer[65536];
        rapidjson::FileReadStream is(fp, readBuffer, sizeof(readBuffer));
        rapidjson::Document doc;
        bool version_match = false;

        if (doc.ParseStream(is).HasParseError()){
            LOG(ERROR) << "Json format is invalid! Json name: " << file.path().c_str();
            goto close_n_cont;
        }
        
        if (!doc.HasMember("winVer") || !doc.HasMember("id")){
            LOG(ERROR) << "Json should have keys 'winVer' and 'id'! FatalError no 'id' or 'winVer'";
            goto close_n_cont;
        }

        for (rapidjson::SizeType i = 0; i < doc["winVer"].Size(); i++){
            if(doc["winVer"][i].GetString() == os.version)
                version_match = true;
        }

        if (doc["winVer"].Size() != 0)
            if (!version_match)
                goto close_n_cont;

        if(!doc.HasMember("base") || !doc.HasMember("file")){
            LOG(ERROR) << "Json should have base and file! FatalError oid: " << doc["id"].GetString();
            goto close_n_cont;
        }
        if(!doc["base"].HasMember("method") || !doc["base"].HasMember("keys")){
            LOG(ERROR) << "Json base should have method and keys! FatalError oid: " << doc["id"].GetString();
            goto close_n_cont;
        }
        if(!doc["file"].HasMember("name") || !doc["file"].HasMember("version") || !doc["file"].HasMember("path")){
            LOG(ERROR) << "Json file should have name, path and version! FatalError oid: " << doc["id"].GetString();
            goto close_n_cont;
        }

        if(!doc["file"]["version"].HasMember("min") || !doc["file"]["version"].HasMember("max")){
            LOG(ERROR) << "Json['file']['version'] should have min atarget_idnd max! FatalError oid: " << doc["id"].GetString();
            goto close_n_cont;
        }


        // This means [base][method] should have "path" key and the target file's full path will be
        // "path" + "file.path" + "file.name"
        if(strcmp(doc["base"]["method"].GetString(), "0") == 0)
        {
            if (!doc["base"]["keys"].HasMember("path"))
            {
                LOG(ERROR) << "Json file: " << doc["id"].GetString() << " has no 'path' key in 'base.method'.";
                goto close_n_cont;
            }
            for(rapidjson::SizeType i = 0; i < doc["base"]["keys"].Size(); i++){
                if (file_control(target_id, db, hash, doc, doc["base"]["keys"][i]["path"].GetString()))
                    break;
            }
        }

        // This means file's base path will be fetched from registry
        // 'base.keys' should have 'key' (registry path) and 'name' (registry name)
        else if(strcmp(doc["base"]["method"].GetString(),"1") == 0)
        {
            if (!doc["base"]["keys"].HasMember("key") || !doc["base"]["keys"].HasMember("name"))
            {
                LOG(ERROR) << "Json file: " << doc["id"].GetString() << " has no 'key' or 'name' key in 'base.keys'.";
                goto close_n_cont;
            }
            for(rapidjson::SizeType i = 0; i < doc["base"]["keys"].Size(); i++)
            {
                std::string registry_name = doc["base"]["keys"][i]["name"].GetString();

                std::vector<OptionalString> vals;
                RedisLayer::redis.hmget(hash, {
                    "REG/" + registry_name
                    }, std::back_inserter(vals));

                Windows::Registry registry;

                if (vals[0].has_value())
                {
                    registry.data = vals[0].value();
                } 
                else 
                {
                    registry = Windows::get_registry(doc["base"]["keys"][i]["key"].GetString(),
                                                     registry_name,
                                                     Windows::RegistryType::REG_SZ);

                    RedisLayer::redis.hset(hash,
                        "REG/" + registry_name,
                        registry.data
                    );
                }

                if (file_control(target_id, db, hash, doc, registry.data))
                    break;
            }
        }
            
        if (doc.HasMember("registry-checks")){ //this means if there is no registry-checks field in json file whole package is vulnerable so we should check "base"
            for (rapidjson::SizeType i = 0; i < doc["registry-checks"].Size(); i++){
                if(!doc["registry-checks"][i].HasMember("key")  || !doc["registry-checks"][i].HasMember("value") ||
                   !doc["registry-checks"][i].HasMember("name") || !doc["registry-checks"][i].HasMember("type")){
                    LOG(ERROR) << "Json registry-checks should have key, name and value! FatalError oid: " << doc["id"].GetString();
                    continue;
                }

                Windows::Registry reg = Windows::get_registry(
                    doc["registry-checks"][i]["key"].GetString(),
                    doc["registry-checks"][i]["name"].GetString(),
                    Windows::reg_str_to_type(doc["registry-checks"][i]["type"].GetString()));

                if (reg.data.empty())
                    continue;

                if (reg.data != doc["registry-checks"][i]["value"].GetString())
                {
                    LOG(DEBUG) << "Registry error";
                    db.insert_one( "dynamicreport", document{}
                        << "static_report" << doc["id"].GetString()
                        << "dynamic_report" << "Current registry: " + reg.data + std::string("\nShould be: ") + 
                                            doc["registry-checks"][i]["value"].GetString()
                        << "target" << target_id
                        << finalize);
                }
            }
        }   
        
       close_n_cont:
        fclose(fp);
     }
}
