//
// Created by aeryz on 4/25/20.
//

#include "ftp.h"
#include <cstring>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>

using bsoncxx::builder::stream::document;
using bsoncxx::builder::stream::finalize;

void send_all(int sockfd, const std::string& buffer)
{
    std::size_t n;
    const char* p = buffer.c_str();
    std::size_t len = buffer.size();
    while (len > 0) {
        n = send(sockfd, p, len, 0);
        if (n < 0) {
            close(sockfd);
            throw std::runtime_error("Send error occured");
        }
        p += n;
        len -= n;
    }
}

std::string read_all(int sockfd)
{
    char buffer[512] = { 0 };

    int n = recv(sockfd, buffer, 512, 0);
    std::string buffer_str(reinterpret_cast<char const*>(buffer), n);

    if (n < 0) {
        close(sockfd);
        throw std::runtime_error("Socket read error.");
    }

    return buffer_str;
}

int create_socket(const char* ip, unsigned port)
{
    struct sockaddr_in server_addr;
    int sockfd;

    memset(&server_addr, 0, sizeof(server_addr));

    if (inet_pton(AF_INET, ip, &(server_addr.sin_addr)) < 0) {
        throw std::runtime_error("Inet address is not valid. " + std::string(ip));
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        throw std::runtime_error("Socket error.");
    }

    if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        close(sockfd);
        throw std::runtime_error("Socket error.");
    }

    return sockfd;
}

bool FTP::login(std::vector<std::string> excluding_functions, Credentials credentials, std::string ip_address)
{
    if(excluding_functions.size() != 0){
        for(std::string &func: excluding_functions){
            if(func == "ftp")
                return false;
        }
    }
    char buffer[256];
    std::string response;
    int sockfd;
    try{
        sockfd = create_socket(ip_address.c_str(), 21);
    }
    catch(...)
    {
        std::cout << "Socket error" << "\n";
        return 0;
    }
     
    response = read_all(sockfd);

    snprintf(buffer, 256, "USER %s\r\n", credentials.username.c_str());
    send_all(sockfd, buffer);

    response = read_all(sockfd);

    snprintf(buffer, 256, "PASS %s\r\n", credentials.password.c_str());
    send_all(sockfd, buffer);

    response = read_all(sockfd);

    close(sockfd);
    
    return response.find("Login successful") != std::string::npos || response.find("Already logged in") != std::string::npos;
}

void FTP::ftp_login_call(std::vector<std::string> excluding_functions, std::vector<std::string> ip_addresses, const DatabaseCtrl &db, const bsoncxx::types::b_oid target_id)
{
    if(excluding_functions.size() != 0){
        for(std::string &func: excluding_functions){
            if(func == "ftp")
                return;
        }
    }

    std::vector<FTP::Credentials> creds;
    
    for(auto &ip: ip_addresses)
    {
        creds.push_back(FTP::Credentials({"anonymous",""}));
    }

    /*std::vector<int> indexes = login(creds);
    

        for(auto &index: indexes)
        {
            std::cout << "Anonymous login is enabled on ip: " << ip_addresses[index] << "\n";
            db.insert_one("dynamicreport", document{}
                                    << "static_report" << ""
                                    << "dynamic_report" << "Anonymous login is enabled."
                                    << "target" << target_id
                                    << finalize);
        }
*/
}
