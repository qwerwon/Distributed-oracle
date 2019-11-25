// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>
#include <netinet/in.h>

#include <thread>
#include <iostream>
#include <signal.h>
#include <unistd.h>
#include "oracle_u.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

struct report{
    int index;
    unsigned int report_len;
    uint8_t public_key[512];
    size_t public_key_size;
    uint8_t report_data[5096];
    size_t report_data_size;
};

struct data_msg{
    int index;
    unsigned int msg_len;
    // Additional attributes
};

int sock, my_index, oracle_num;
struct sockaddr_in my_addr;
struct sockaddr_in* peer_list;

oe_enclave_t* create_enclave(const char* enclave_path)
{
    oe_enclave_t* enclave = NULL;

    printf("Host: Enclave library %s\n", enclave_path);
    oe_result_t result = oe_create_oracle_enclave(
        enclave_path,
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave);

    if (result != OE_OK)
    {
        printf(
            "Host: oe_create_oracle_enclave failed. %s",
            oe_result_str(result));
    }
    else
    {
        printf("Host: Enclave successfully created.\n");
    }
    return enclave;
}

void terminate_enclave(oe_enclave_t* enclave)
{
    oe_terminate_enclave(enclave);
    printf("Host: Enclave successfully terminated.\n");
}

int init_peer_config(){
    char buf[30];
    FILE* peer_fp = fopen("../peer_list.conf", "r+");

    printf("Host: read peer info from configure file.\n");
     // index:<index>
    fgets(buf, sizeof(buf), peer_fp);
    {
        const char* option = "index:";
        int param_len = strlen(option);
        if (strncmp(buf, option, param_len) == 0)
            my_index = atoi((char*)(buf + param_len));
        else{
            fprintf(stderr, "peer_list.conf\nindex:<index>\n#ofOracle:<total # of oracle nodes>\nip list of peer...\n");
            return -1;
        }
    }

    // #ofOracle:<total # of oracle nodes>
    fgets(buf, sizeof(buf), peer_fp);
    {
        const char* option = "#ofOracle:";
        int param_len = strlen(option);
        if (strncmp(buf, option, param_len) == 0)
            oracle_num = atoi((char*)(buf + param_len));
        else{
            fprintf(stderr, "peer_list.conf\nindex:<index>\n#ofOracle:<total # of oracle nodes>\nip list of peer...\n");
            return -1;
        }
    }
    
    peer_list = (struct sockaddr_in*)malloc(sizeof(sockaddr_in) * oracle_num);

    for(int i = 0; i < oracle_num; i++){

        fgets(buf, sizeof(buf), peer_fp);

        if (buf[strlen(buf) - 1] == '\n')
            buf[strlen(buf) - 1] = '\0';

        if (i == my_index){
            bzero(&my_addr, sizeof(struct sockaddr_in));
            my_addr.sin_family = AF_INET;
            my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
            my_addr.sin_port = htons(4000);
        }

        bzero(&peer_list[i], sizeof(struct sockaddr_in));
        peer_list[i].sin_family = AF_INET;
        peer_list[i].sin_addr.s_addr = inet_addr(buf);
        peer_list[i].sin_port = htons(4000);

        printf("Host: %d-th oracle ip addr is %s\n", i, buf);
    }
    
    return 1;
}

void recv_report(oe_enclave_t* enclave){
    struct sockaddr_in sender_addr;
    struct report pkt;
    uint8_t* pem_key = NULL;
    size_t pem_key_size = 0;
    uint8_t* remote_report = NULL;
    size_t remote_report_size = 0;
    oe_result_t result = OE_OK;
    int cnt = 1, ret;
    socklen_t addrlen = 10;
    
    printf("Host: recv_report...\n");
    while(cnt != oracle_num){
        // ECALL: verify_report_and_set_pubkey
        recvfrom(sock, &pkt, sizeof(struct report), 0, (struct sockaddr*)&sender_addr, &addrlen);
        printf("!TEST! remote report size = %lu\n", sizeof(pkt.report_data));

        pem_key = pkt.public_key;
        pem_key_size = pkt.public_key_size;
        remote_report = pkt.report_data;
        remote_report_size = pkt.report_data_size;

        printf("Host: verifying %d-th oracle nodes remote report and public key...\n", pkt.index);
        result = verify_report_and_set_pubkey(
            enclave,
            &ret,
            pem_key,
            pem_key_size,
            remote_report,
            remote_report_size);

        if ((result != OE_OK) || (ret != 0)){
            printf(
                "Host: verify_report_and_set_pubkey failed. %s",
                oe_result_str(result));
            if (ret == 0)
                ret = 1;
        }
        else
            cnt++;

        free(pem_key);
        pem_key = NULL;
        free(remote_report);
        remote_report = NULL;
    }
}

void broadcast_report(uint8_t* pem_key, size_t pem_key_size, uint8_t* remote_report, size_t remote_report_size){
    struct report pkt;
    int status;
    pkt.index = my_index;
    memcpy(pkt.public_key, pem_key, pem_key_size);
    pkt.public_key_size = pem_key_size;
    memcpy(pkt.report_data, remote_report, remote_report_size);
    pkt.report_data_size = remote_report_size;

    printf("Host: broadcasting report to oracle nodes...\n");
    for(int i = 0; i < oracle_num; i++){
        if (i == my_index) continue;
        
        status = sendto(sock, &pkt, sizeof(struct report), 0, (struct sockaddr*)&(peer_list[i]), sizeof(struct sockaddr_in));
        if (status < 0){
            fprintf(stderr, "send to %d-th oracle node fail.\n", i);
            return;
        }
    }
}

int main(int argc, const char* argv[])
{
    oe_enclave_t* enclave = NULL;
    uint8_t* encrypted_msg = NULL;
    size_t encrypted_msg_size = 0;
    oe_result_t result = OE_OK;
    int ret = 1;
    uint8_t* pem_key = NULL;
    size_t pem_key_size = 0;
    uint8_t* remote_report = NULL;
    size_t remote_report_size = 0;

    /* Additional vars  */
    char buf[20];
    int clntlen, flag = 1;
    std::thread worker;
    //struct sigaction act;

    /* ./host enclave.signed -port:<port> */
    /* Check argument count. */
    if (argc != 3){
        fprintf(stderr, "Usage: %s ENCLAVE_PATH -port:<port>\n", argv[0]);
        return -1;
    }

    /* Read config file and init peer & socket info. */
    if (init_peer_config() < 0)
        return -1;

    /* Start of initialization for socket. */
    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0){
        fprintf(stderr, "Cannot open send stream socket.\n");
        return -1;
    }

    //sigaction(SIGCHLD, &act, 0);

    /* Create a enclave. */
    printf("Host: Creating a enclaves\n");
    enclave = create_enclave(argv[1]);
    if (enclave == NULL)
        goto exit;
    
    /* ECALL:Generate report and key pair. */
    /* Private: invisible encryption key to outside. */
    /* Pubkey: all msgs among oracle nodes would be verified with this key. */
    printf("Host: requesting a remote report and the encryption key from 1st "
           "enclave\n");
    result = get_remote_report_with_pubkey(
        enclave,
        &ret,
        &pem_key,
        &pem_key_size,
        &remote_report,
        &remote_report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_report_and_set_pubkey failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    printf("Host: enclave's public key: \n%s", pem_key);


    // bind
    if (bind(sock, (struct sockaddr *)&my_addr, sizeof(my_addr)) < 0){
        fprintf(stderr, "Cannot bind local address.\n");
        goto exit;
    }
   
    /* Receive all reports from other oracle ndoes. */
    worker = std::thread(recv_report, enclave);
    
    while(1){
        printf("Press enter...(broadcast report & public key)\n");
        fgets(buf, sizeof(buf), stdin);
        if (buf[0] == '\n')
            break;
    }

    /* Broadcast to all oracle nodes. */
    if (flag){
        flag--;
        broadcast_report(pem_key, pem_key_size, remote_report, remote_report_size);
    }

    /* Wait until all reports got verified. */
    worker.join();
    
    // Set up tls connection between oracle nodes.
    /*printf("Host: calling setup_tls_server\n");
    ret = setup_tls_server(enclave, &ret, target_port);
    if (ret != 0)
    {
        printf("Host: setup_tls_server failed\n");
        goto exit;
    }*/
    
    /* ???????????????????????
    free(pem_key);
    pem_key = NULL;
    free(remote_report);
    remote_report = NULL;
    */

    /*
    printf("Host: Requesting a remote report and the encryption key from "
           "2nd enclave=====\n");
    result = get_remote_report_with_pubkey(
        enclave_b,
        &ret,
        &pem_key,
        &pem_key_size,
        &remote_report,
        &remote_report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_report_and_set_pubkey failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    printf("Host: 2nd enclave's public key: \n%s", pem_key);

    printf("Host: Requesting first enclave to attest 2nd enclave's "
           "remote report and the public key=====\n");
    result = verify_report_and_set_pubkey(
        enclave,
        &ret,
        pem_key,
        pem_key_size,
        remote_report,
        remote_report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_report_and_set_pubkey failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    free(pem_key);
    pem_key = NULL;
    free(remote_report);
    remote_report = NULL;

    printf("Host: Remote attestation Succeeded\n");

    // Free host memory allocated by the enclave.
    free(encrypted_msg);
    encrypted_msg = NULL;
    ret = 0;
    */

exit:
    if (pem_key)
        free(pem_key);

    if (remote_report)
        free(remote_report);

    if (encrypted_msg != NULL)
        free(encrypted_msg);

    printf("Host: Terminating enclaves\n");
    if (enclave)
        terminate_enclave(enclave);

    printf("Host:  %s \n", (ret == 0) ? "succeeded" : "failed");
    return ret;
}

