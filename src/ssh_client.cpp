
#include "ssh_client.h"

#include <cstdlib>
#include <iostream>
#include <libssh/libssh.h>
//#include <libssh2.h>

#include "data_types.h"

// TODO: global session?

ssh_session session;
//LIBSSH2_SESSION session2;

bool SSHClient::start_session(unsigned int port, const std::string& ip, const Credentials& cred){
          
    session = ssh_new();
    ssh_options_set(session, SSH_OPTIONS_HOST, ip.c_str());
    ssh_options_set(session, SSH_OPTIONS_USER, cred.username.c_str());
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);

    if (ssh_connect(session) != SSH_OK)
        return false;

    if(cred.password == ""){ //this means public key authentication

        ssh_key my_key;
        ssh_pki_import_privkey_file(cred.public_key_path.c_str(), NULL, NULL, NULL, &my_key);
        if(ssh_userauth_publickey(session, cred.username.c_str(), my_key) != SSH_AUTH_SUCCESS)
            return false;

    }
    else{
        if (ssh_userauth_password(session, nullptr, cred.password.c_str()) != SSH_AUTH_SUCCESS)
            return false;
    }
    return true;
}


std::string SSHClient::exec_cmd(const std::string& cmd)
{
    ssh_channel channel;
    char buffer[256];
    int n_bytes;

    channel = ssh_channel_new(session);
    if (channel == nullptr) {
        throw std::runtime_error("Couldn't initiate an ssh channel.");
    }

    if (ssh_channel_open_session(channel) != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        throw std::runtime_error("Couldn't open a SSH session.");
    }

    if (ssh_channel_request_exec(channel, cmd.c_str()) != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        throw std::runtime_error("Failed to execute remote command.");
    }

    std::string output;

    n_bytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    // TODO: Timeout?
    while (n_bytes > 0) {
        output.append(buffer, n_bytes);
        n_bytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return output;
}

void SSHClient::free_session()
{
    ssh_free(session);
}