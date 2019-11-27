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
#include <mutex>
#include <iostream>
#include <signal.h>
#include <unistd.h>
#include "oracle_u.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define REVOLVER(a, b) (a < 0) ? b - 1 : ((a == b) ? 0 : a)

struct report{
    int index;
    unsigned int report_len;
    uint8_t public_key[512];
    size_t public_key_size;
    uint8_t report_data[5096];
    size_t report_data_size;
};

/* message type:
 * 0x01 data delivery
 * 0x02 data request
 * 0x04 leader election
 * 0x08 reelection */

struct message{
    int index;
    char type;
    unsigned int msg_len;
    double data;
    // Additional attributes
};

int *sock, my_index, oracle_num;
struct sockaddr_in my_addr;
struct sockaddr_in* peer_list;
std::mutex mtx_lock;

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
    
    printf("# of oracle = %d, my index = %d\n", oracle_num, my_index);

    peer_list = (struct sockaddr_in *)malloc(sizeof(sockaddr_in) * oracle_num);
    sock = (int *)malloc(sizeof(int) * oracle_num);

    for(int i = 0; i < oracle_num; i++){

        fgets(buf, sizeof(buf), peer_fp);

        if (buf[strlen(buf) - 1] == '\n')
            buf[strlen(buf) - 1] = '\0';

        if (i == my_index){
            bzero(&my_addr, sizeof(struct sockaddr_in));
            my_addr.sin_family = AF_INET;
            my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
            my_addr.sin_port = htons(4000);
            continue;
        }

        bzero(&peer_list[i], sizeof(struct sockaddr_in));
        peer_list[i].sin_family = AF_INET;
        peer_list[i].sin_addr.s_addr = inet_addr(buf);
        peer_list[i].sin_port = htons(4000);

        printf("Host: %d-th oracle ip addr is %s\n", i, buf);
    }

    return 1;
}

void accept_connection(int data){
    int new_socket = 0, cnt, flag = oracle_num / 2;
    struct sockaddr_in new_addr;
    socklen_t addr_size = sizeof(new_addr);
    printf("Host: waiting for accept()... \n");
    while(flag){
        new_socket = accept(sock[my_index], (struct sockaddr*)&new_addr, &addr_size);

        if (new_socket < 0){
            fprintf(stderr, "accept fail.\n");
            exit(0);
        }

        else if (new_socket == 0)
            continue;

        /* Warning:
         * Only odd 'oracle_num' is allowed. */
        for(int i = my_index + 1, cnt = 0; cnt < oracle_num / 2; i++, cnt++){
            i = REVOLVER(i, oracle_num);
            if (strcmp(inet_ntoa(new_addr.sin_addr), inet_ntoa(peer_list[i].sin_addr)) == 0){
                printf("accept %d-th node(%s:%d)\n", i,
                        inet_ntoa(new_addr.sin_addr),
                        ntohs(new_addr.sin_port));
                sock[i] = new_socket;
                memcpy(&peer_list[i], &new_addr, sizeof(struct sockaddr_in));
                flag--;
                break;
            }
        }

        if (cnt > oracle_num / 2)
            fprintf(stderr, "Unauthorized node connection.\n"); 
    }
    printf("Host: accep done\n");
}

int connect_to_peer(){
    std::thread acceptor;
    int ret, flag[oracle_num], connect_cnt = oracle_num / 2;

    /* Warning:
     * Only odd 'oracle_num' is allowed. */
    for (int i = 0; i < oracle_num; i++)
        flag[i] = 1;

    // Socket generation
    for(int i = 0; i < oracle_num; i++){
        sock[i] = socket(PF_INET, SOCK_STREAM,0);
        if (sock[i] < 0){
            fprintf(stderr, "socket generation fail.\n");
            return -1;
        }
    }

    printf("My sin_family = %d, sin_port = %d, sin_addr = %s\n", 
            my_addr.sin_family, 
            ntohs(my_addr.sin_port),
            inet_ntoa(my_addr.sin_addr));

    // Binding
    ret = bind(sock[my_index], (struct sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0){
        fprintf(stderr, "bind fail %d.\n", ret);
        return -1;
    }

    if (listen(sock[my_index], 10) < 0){
        fprintf(stderr, "listen fail.\n");
        return -1;
    }

    // Accept
    acceptor = std::thread(accept_connection, my_index);

    // Connect

    /* Warning:
     * Only odd 'oracle_num' is allowed. */
    while(connect_cnt){
        for (int i = my_index - 1, cnt = 0; cnt < oracle_num / 2; i--, cnt++){
            i = REVOLVER(i, oracle_num);
            if (flag[i] == 0)   continue;
            printf("Host: connect to %d-th node(%s)...\n", i, inet_ntoa(peer_list[i].sin_addr));
            if (connect(sock[i], (struct sockaddr *)&peer_list[i], sizeof(peer_list[i])) > 0){
                printf("Host: connection to %d-th node(%s:%d) succeed.\n", i, 
                        inet_ntoa(peer_list[i].sin_addr),
                        ntohs(peer_list[i].sin_port));
                connect_cnt--;
                flag[i] = 0;
            }
        }
        usleep(1000000);
    }
      
    if (acceptor.joinable() == true)
        acceptor.join();

    return 1;
}

void recv_report(oe_enclave_t* enclave, int index){
    struct report *rcvd_report;
    uint8_t* pem_key = NULL;
    size_t pem_key_size = 0;
    uint8_t* remote_report = NULL;
    size_t remote_report_size = 0;
    oe_result_t result = OE_OK;
    int ret, flag = 1;

    while(flag){
        if (recv(sock[index], (char *)rcvd_report, sizeof(struct report), 0) > 0){
            printf("Listener-%d: report received.\n", index);
            
            memcpy(pem_key, rcvd_report->public_key, rcvd_report->public_key_size);
            pem_key_size = rcvd_report->public_key_size;
            memcpy(remote_report, rcvd_report->report_data, rcvd_report->report_data_size);
            remote_report_size = rcvd_report->report_data_size;
            
            mtx_lock.lock();
            result =  verify_report_and_set_pubkey(
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
            }
            else{
                printf(
                    "Host: %d-th oracle's remote attestation succeeded.\n",
                    index);
                flag = 0;
            }
            mtx_lock.unlock();

            free(pem_key);
            pem_key = NULL;
            free(remote_report);
            remote_report = NULL;
        }
    }
}

int broadcast_report(uint8_t* pem_key, size_t pem_key_size, uint8_t* remote_report, size_t remote_report_size){
    struct report pkt;
    int status;
    pkt.index = my_index;
    memcpy(pkt.public_key, pem_key, pem_key_size);
    pkt.public_key_size = pem_key_size;
    memcpy(pkt.report_data, remote_report, remote_report_size);
    pkt.report_data_size = remote_report_size;

    printf("Host: broadcasting report to oracle nodes...\n");
    for(int i = 0; i < oracle_num; i++){
        if (i == my_index)  continue;

        printf("Host: send to node:%s:%d\n", inet_ntoa(peer_list[i].sin_addr), ntohs(peer_list[i].sin_port));
        if (send(sock[i], (char *)&pkt, sizeof(struct report), 0) <= 0){
            fprintf(stderr, "send to %d-th oracle node fail.\n", i);
            return -1;
        }
    }
    printf("Host: broadcasts successfully.\n");
    return 1;
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
    struct report my_report;
    char buf[20];
    int clntlen, flag = 1;
    std::thread listener[10];
    //struct sigaction act;

    /* ./host enclave.signed -port:<port> */
    /* Check argument count. */
    if (argc != 3){
        fprintf(stderr, "Usage: %s ENCLAVE_PATH -port:<port>\n", argv[0]);
        return -1;
    }

    /* Read config file and init peer & socket info. */
    if (init_peer_config() < 0){
        fprintf(stderr, "config file read fail.\n");
        return -1;
    }

    /* Create a enclave. */
    printf("Host: Creating a enclaves\n");
    enclave = create_enclave(argv[1]);
    if (enclave == NULL)
        goto exit;
    
    /* ECALL:Generate report and key pair. */
    /* Private: invisible encryption key to outside. */
    /* Pubkey: all msgs among oracle nodes would be verified with this key. */
    printf("Host: generating a remote report with encryption key\n");
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
            "Host: get_remote_report_with_pubkey failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    printf("Host: enclave's public key: \n%s", pem_key);
    printf("Host: key size = %zu, report size = %zu\n", pem_key_size, remote_report_size);

    if (connect_to_peer() < 0){
        fprintf(stderr, "Host: connection fail.\n");
        goto exit;
    }

    for (int i = 0; i < oracle_num; i++){
        if (i == my_index)  continue;
        listener[i] = std::thread(recv_report, enclave, i);
    }

    if (broadcast_report(pem_key, pem_key_size, remote_report, remote_report_size) < 0){
        fprintf(stderr, "Host: broadcast report fail.\n");
        goto exit;
    }

    for (int i = 0; i < oracle_num; i++){
        if (i == my_index)  continue;
        listener[i].join();
    }

    printf("Host: all oracle nodes verified.\n");

    // Set up tls connection between oracle nodes.
    /*printf("Host: calling setup_tls_server\n");
    ret = setup_tls_server(enclave, &ret, target_port);
    if (ret != 0)
    {
        printf("Host: setup_tls_server failed\n");
        goto exit;
    }*/

 
    // Free host memory allocated by the enclave.
 
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

