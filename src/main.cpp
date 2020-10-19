
// Std
#include <signal.h>
#include <iostream>
#include <unistd.h>  // fork()
#include <sys/stat.h>  // Stat macros
#include <sys/wait.h>  // waitpid()
#include <netinet/in.h>  // Target IP check
#include <arpa/inet.h>  // Target IP check
#include <vector>

#if defined(__cpp_lib_filesystem)
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

// External

// External local
#include "vendor/rapidjson/document.h"  // JSON Document
#include "vendor/easylogging++/easylogging++.h"  // Logging

// Internal
#include "alive_test.h"
#include "../modules/call_external_modules.h"
#include "os_finder_ssh.h"
#include "config.h"
#include "database_ctrl.h"
#include "data_types.h"
#include "ssh_client.h"
#include "../modules/local_security.h"
#include "../modules/windows_local_security.h"
#include "../modules/brute_force.h"
#include "../modules/ftp.h"

#include "redis_namespace.h"

#include <mongocxx/instance.hpp>

// TODO: DB requests error handling

using bsoncxx::builder::stream::document;
using bsoncxx::builder::stream::finalize;
using bsoncxx::builder::stream::open_document;
using bsoncxx::builder::stream::close_document;

// Easyloggingpp initializer
INITIALIZE_EASYLOGGINGPP

#define CONCURRENT_TARGET_COUNT 4

bool should_stop = false;

std::vector<std::string> split(const std::string &text, char sep)
{
    std::vector<std::string> tokens;
    std::size_t start=0, end =0;
    while((end = text.find(sep,start)) != std::string::npos){
        tokens.emplace_back(text.substr(start,end-start));
        start = end + 1;
   } 
    tokens.emplace_back(text.substr(start));    

    return tokens;
}

void run(const bsoncxx::types::b_oid scan_id, const Parameters& params, const std::string& target_ip, Config& cfg, bool already_brute_forced)
{
    const DatabaseCtrl db("ztp-dev");

    const auto target = db.insert_one("target", document{}
            << "ip"        << target_ip
            << "os"        << ""
            << "scan_hash" << scan_id
            << finalize);

    if (!target) {
        LOG(ERROR) << "Couldn't insert target document. Scan won't continue for: " << target_ip;
        return;
    }

    if (AliveTest::run(target_ip, params.nmap_option)) {
        LOG(DEBUG) << target_ip << ": Host is up" << std::endl;

        // TODO: Will be replaced with redis
        Credentials cred{params.ssh_username, params.ssh_password, params.public_key_path};


        if (!SSHClient::start_session(params.ssh_port, target_ip, cred)) {
            db.insert_one("dynamicreport", document{}
                    << "static_report"  << ""
                    << "dynamic_report" << "SSH login failed."
                    << "target"         << target -> inserted_id().get_oid()
                    << finalize);
            LOG(DEBUG) << target_ip << ": SSH Login failed";
            return;
        }

        OSInfo os_info;
        if (!OSFinderSSH::run(os_info, db, target -> inserted_id().get_oid())) {
            LOG(DEBUG) << target_ip << ": Couldn't determine the operating system.";
            return;
        }

        db.update_one("target", document{} << "_id" << target->inserted_id().get_oid() << finalize, document{}
                << "$set"         << open_document
                << "os"           << os_info.version
                << close_document << finalize);

        const auto ztd_path = cfg.get("ZTD_PATH", "linuxlocalsec");

        if (ztd_path.empty())
            LOG(WARNING) << "'ZTD_PATH:linuxlocalsec' is missing. Linux local security plugin won't run.";
        else{    
            if(os_info.os == "linux"){
                LocalSecurity::Run(os_info, target -> inserted_id().get_oid(), db, ztd_path, params.excluding_functions);

            }
            else if (os_info.os == "windows") {
                WindowsLocalSecurity::Run(os_info, target -> inserted_id().get_oid(), db, cfg.get("ZTD_PATH", "localsec"));
            }
            else {
                LOG(DEBUG) << ": Unknown operating system.";
            }
        }
        
        

        if(FTP::login(params.excluding_functions, FTP::Credentials({"anonymous",""}), target_ip))
        {
            db.insert_one("dynamicreport", document{}
                                    << "static_report" << ""
                                    << "dynamic_report" << "Anonymous login is enabled."
                                    << "target" << target -> inserted_id().get_oid()
                                    << finalize);
        }
    
        //We are brute forcing to the router we can call any ip address since they all in same network.
        
        BruteForce::bruteForceCall(params.brute_force_type, params.brute_force_path, params.targets[0], params.excluding_functions, db, already_brute_forced, target -> inserted_id().get_oid());

        std::vector<std::string> args_for_external_modules{params.ssh_username, params.ssh_password, target_ip, "27017", target -> inserted_id().get_oid().value.to_string() };
        
        //TODO: Path must be absolute path!
        for(const auto &file: fs::directory_iterator("modules/external_modules"))
        {
            if(file.path().extension() != ".py")
                continue;
            ExternalModules::call_external_modules(args_for_external_modules, file.path().filename().replace_extension());
        }
        std::string scan_hash = scan_id.value.to_string();
        std::string hash = scan_hash + "|" + target_ip;

        std::unordered_map<std::string, std::string> hash_map;
        RedisLayer::redis.hgetall(hash, std::inserter(hash_map, hash_map.end()));

        for (const auto& kv: hash_map)
        {
            RedisLayer::redis.hdel(hash, kv.first);
        }

        SSHClient::free_session();
    }
    else {
        LOG(INFO) << target_ip << "Host is down" << std::endl;
        db.insert_one("dynamicreport", document{}
                << "static_report"  << ""
                << "dynamic_report" << "Host is down."
                << "target"         << target -> inserted_id().get_oid()
                << finalize);
    }
};

void handle_sigterm(int)
{
	should_stop = true;
}

inline Parameters get_parameters(const char *data)
{
    rapidjson::Document doc;

    if (doc.Parse(data).HasParseError()) {
        std::cout << "JSON is invalid";
        exit(1);
    }
    
    if(doc.HasMember("external-function-path"))
    {
        try
        {
            fs::copy(doc["external-function-path"].GetString(), "modules/external_modules");
            std::cout << "Given file added to external_modules !\n";
            exit(1);
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
            exit(1);
        }
        
    }
    else
    {
        if (!doc.HasMember("ssh-username") || !doc.HasMember("targets")) {
            std::cout << "Some fields are missing";
            exit(1);
        }

        Parameters params(doc["ssh-username"].GetString());
        
        if(doc.HasMember("ssh-password")){
            try{
                params.ssh_password = doc["ssh-password"].GetString();
            }
            catch (const std::exception& e) {
                std::cout << "Exception occured when setting password";
                exit(1);
            }
        }
        else{
            if(doc.HasMember("public-key-path")){
                try{
                    params.public_key_path = doc["public-key-path"].GetString();
                }
                catch (const std::exception& e) {
                    std::cout << "Exception occured when setting password";
                    exit(1);
                }
            }
            else{
                std::cout << "password or public key must be entered !\n";
                exit(1);
            }
        }

        if(doc.HasMember("brute-force-type")){
            try{
                params.brute_force_type = doc["brute-force-type"].GetString();
            }
            catch (const std::exception& e) {
                std::cout << "Exception occured when setting brute force type";
                exit(1);
            }

            if(doc.HasMember("brute-force-path"))
            {
                try
                {
                    params.brute_force_path = doc["brute-force-path"].GetString();
                }
                catch(const std::exception& e)
                {
                    std::cout << "Exception occured when setting brute force path";
                    exit(1);
                }
                
            }
        }


        if (doc.HasMember("ssh-port")) {
            try {
                params.ssh_port = std::stoi(doc["ssh-port"].GetString());
            }
            catch (const std::exception& e) {
                std::cout << "Port must be a number between 0 and 65535";
                exit(1);
            }
        }

        if (doc.HasMember("nmap")) {
            try {
                params.nmap_option = doc["nmap"].GetString();
            }
            catch (const std::exception& e) {
                std::cout << "Exception occured with nmap option!";
                exit(1);
            }
        }

        if (doc.HasMember("excluding_functions")) {
            try {
                for(const auto& function: doc["excluding_functions"].GetArray()){
                    params.excluding_functions.emplace_back(function.GetString());
                }
            }
            catch (const std::exception& e) {
                std::cout << "Exception occured excluding functions!";
                exit(1);
            }
        }

        if (params.ssh_port < 0 || params.ssh_port > 65535) {
            std::cout << "Port should be between 0 and 65535";
            exit(1);
        }

        // Checking if IP addresses are valid
        struct sockaddr_in sa{}; // Dumb variable not to get seg fault
        for(const auto& target: doc["targets"].GetArray()) {
            const char* target_cstr = target.GetString();
            if (!inet_pton(AF_INET, target_cstr, &sa.sin_addr)) {
                std::cout << "IP address is invalid";
                exit(1);
            }
            params.targets.emplace_back(target_cstr);
        }

        return params;
    }
}

inline void daemonize()
{
    pid_t pid, sid;

    pid = fork();
    if (pid < 0) {
        std::cout << "Fork error";
        exit(1);
    }

    if (pid > 0) {
        std::cout << "Process started with the pid: " << getpid();
        exit(0);
    }

    umask(0);

    sid = setsid();
    if (sid < 0)
        exit(1);

    chdir("/tmp");

    signal(SIGTERM, handle_sigterm);

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

void manage_targets(const Parameters& params, Config& cfg)
{
    const DatabaseCtrl db("ztp-dev");

    const int n_conc_targets = params.targets.size() >= CONCURRENT_TARGET_COUNT
            ? CONCURRENT_TARGET_COUNT : static_cast<int>(params.targets.size());

    const auto date_now = bsoncxx::types::b_date(std::chrono::system_clock::now());

    const auto scan_doc = db.insert_one("scan", document{}
            << "creation_date" << date_now
            << "end_date"      << date_now
            << "status"        << ScanStatus::ONGOING
            << "pid"           << static_cast<int>(getpid())
            << finalize);

    if (!scan_doc)
        LOG(FATAL) << "Error while creating database entry for scan";

    // TODO: Concurrent targets must have a limit
	pid_t child_pids[n_conc_targets];
    memset(child_pids, 0, sizeof(pid_t) * n_conc_targets);

    bool can_continue = true;
    int n_errs = 0;
    auto iter = params.targets.begin();

    while(can_continue) {
		if (should_stop) {
			for (const auto pid: child_pids) {
                if (kill(pid, SIGKILL) < 0) {
                    LOG(ERROR) << "Error while killing the process: " << pid << " with errno: " << errno;
                    continue;
                }
			}
			exit(0);
		}

        for (int i = 0; i < n_conc_targets; ++i) {
            // Empty slot exists, so process can be spawned if there are any target
            if (child_pids[i] == 0) {
                if (params.targets.end() == iter)
                    continue;

                child_pids[i] = fork();
                if (child_pids[i] < 0) {
                    child_pids[i] = 0;
                    LOG(ERROR) << "Error returned from fork() in: " << (*iter) << " with errno: " << errno;

                    // We don't want an endless loop, also we don't want to halt immediately
                    if (15 < ++n_errs) {
                        LOG(ERROR) << "Too many fork errors. No new process will be spawned.";
                        iter = params.targets.end();
                        goto cont;
                    }
                }
                else if (child_pids[i] == 0) {
                    run(scan_doc->inserted_id().get_oid(), params, (*iter), cfg, i != 0);
                    exit(0);
                }
                // TODO: More logical solution is needed
                usleep(500000);
                ++iter;
            }
            else
            {
                int status; // TODO: unused
                const pid_t end_pid = waitpid(child_pids[i], &status, WNOHANG | WUNTRACED);
                // TODO: Exit status will be saved for each target
                if (end_pid > 0)
                    child_pids[i] = 0;
            }
        }

        if (iter == params.targets.end()) {

            for (const pid_t p: child_pids) {
                if (p)
                    goto cont;
            }
            can_continue = false;
        }
        cont:;

        sleep(1);
    }

    db.update_one("scan", document{} << "_id" << scan_doc->inserted_id().get_oid() << finalize, document{}
            << "$set"     << open_document
            << "end_date" << bsoncxx::types::b_date(std::chrono::system_clock::now())
            << "status"   << ScanStatus::FINISHED
            << close_document
            << finalize);
}

inline void initialize_logging()
{
    const char* log_conf_path = "/etc/ztp/ztplogging.conf";
    // We need to check if path exists because el::Configuration initializer does not throw if file doesn't exist
    if (!fs::exists(log_conf_path) || !fs::is_regular_file(log_conf_path))
        exit(1);

    el::Configurations conf(log_conf_path);
    el::Loggers::reconfigureAllLoggers(conf);
}

int main(int argc, char* const* argv)
{
    if (argc < 2) {
        LOG(FATAL) << "Program needs an argument but argc is: " << argc;
        exit(1);
    }

    Parameters params = get_parameters(argv[1]);
    //daemonize();
    initialize_logging();

    Config cfg;
    cfg.parse();

    // To enable Mongo driver
    mongocxx::instance inst{};
    manage_targets(params, cfg);
    return 0;
}
