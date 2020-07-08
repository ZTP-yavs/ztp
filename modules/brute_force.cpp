#include "brute_force.h"
#include <stdio.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <unistd.h> 
#include <string.h> 
#include <fstream>
#include <iostream>
#include <vector>

using bsoncxx::builder::stream::document;
using bsoncxx::builder::stream::finalize;

std::vector<std::string> splitVector(const std::string &text, char sep)
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

bool BruteForce::bruteForceRouter(std::string ip, std::string username, std::string password){
    int sock = 0, valread; 
    char buffer[1024] = {0}; 

    struct timeval timeout;      
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    struct sockaddr_in serv_addr; 
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(23);

    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) < 0) { 
        printf("\n Socket creation error \n");
        exit(1);
        return -1; 
    }

    if (setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, 
                    (char *)&timeout, sizeof(timeout)) < 0){
        printf("setsockopt failed\n");
        exit(1);
    }

    if(setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, 
                (char *)&timeout, sizeof(timeout)) < 0){
        printf("Cannot Set SO_SNDTIMEO for socket\n");
        exit(1);
    }
    
    if(inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr)<=0)  { 
        printf("\nInvalid address/ Address not supported \n"); 
        exit(1);
    } 
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) { 
        printf("\nConnection Failed \n"); 
        exit(1);
        return -1; 
    }
       
    valread = read( sock , buffer, 1024); 
    
    valread = read( sock , buffer, 1024); 

    for (int i = 0; i < username.length(); ++i){
        valread = sendto(sock, &username[i], 1, 0, NULL, 0);
        read(sock, buffer, 10);
    }

    sendto(sock, "\r\0", 2, 0, NULL, 0);
    read(sock, buffer, 10);

    memset(buffer, '\0', 1024);
    read(sock, buffer, 1024);

    for (int i = 0; i < password.length(); ++i)
    {
        valread = sendto(sock, &password[i], 1, 0, NULL, 0);
    }
    sendto(sock, "\r\0", 2, 0, NULL, 0);
    read(sock, buffer, 10);

    memset(buffer, '\0', 1024);
    read(sock, buffer, 1024);
    std::string bufferToStr(buffer);
    if (bufferToStr.find("incorrect") != std::string::npos || bufferToStr == "") {
        return false;
    }
    else{
        return true;
    }
}


void BruteForce::bruteForceCall(std::string bruteForceType, std::string brute_force_path, std::string ip, std::vector<std::string> excluding_functions, const DatabaseCtrl &db, bool already_checked, const bsoncxx::types::b_oid target_id){
    if(already_checked)
        return;
    if(excluding_functions.size() != 0){
        for(std::string &func: excluding_functions){
            if(func == "brute_force")
                return;
        }
    }
    std::vector<std::string> parsed_ip = splitVector(ip, '.');
    std::string router_ip = parsed_ip[0] + + "." + parsed_ip[1] + "." + parsed_ip[2] + "." + "1";

    std::fstream newfile;
    std::string fileName;
    std::vector<std::string> usernames = {"root","admin",""};
    
    //Needed to add bigger password dictionary for medium and heavy options.
    if(bruteForceType == "light"){
        fileName = "/etc/ztp/common_passwords_light.txt";
    }
    else if(bruteForceType == "medium"){
        fileName = "/etc/ztp/common_passwords_light.txt";
    }
    else if(bruteForceType == "heavy"){
        fileName = "/etc/ztp/common_passwords_light.txt";
    }
    else if(bruteForceType == "optional")
    {
        if(brute_force_path == "/")
            return;
        fileName = brute_force_path;
    }
    //else if bruteforcetype == normal
    //else if bruteforcetype == heavy
    //else => on this case we will read the path they gave us for password dictionary.

    newfile.open(fileName, std::ios::in); //open a file to perform read operation using file object
    if (newfile.is_open()){
       
        std::string password;
        for(auto &username: usernames){
            while(getline(newfile, password)){ 
                
                if(bruteForceRouter(router_ip, username, password)){
                    db.insert_one("dynamicreport", document{}
                                    << "static_report" << ""
                                    << "dynamic_report" << "Routers password is very weak you should change that!"
                                    << "target" << target_id
                                    << finalize);
                    return;
                }
            }
        }
      newfile.close(); 
   }
}
