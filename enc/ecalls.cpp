// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include "../common/dispatcher.h"
#include "./common/oracle_t.h"
#include <openenclave/enclave.h>
#include "oracle_pubkey_list.h"

// Addtional code
#define ENCLAVE_SECRET_DATA_SIZE 16

uint8_t g_enclave_secret_data[ENCLAVE_SECRET_DATA_SIZE] =
    {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,16};

// OTHER_ENCLAVE_PUBLIC_KEY -> public key list of all oracle nodes(not enclave-generated key, but explicitly generated)
// Warning! hard coded(as number of oracle)
enclave_config_data_t config_data = {g_enclave_secret_data,
                                        {OTHER_ENCLAVE_PUBLIC_KEY[0],
                                        OTHER_ENCLAVE_PUBLIC_KEY[1],
                                        OTHER_ENCLAVE_PUBLIC_KEY[2]},
                                     sizeof(OTHER_ENCLAVE_PUBLIC_KEY[0])};

static const uint8_t oracle_number = (uint8_t) sizeof(OTHER_ENCLAVE_PUBLIC_KEY) / ENCLAVE_PUBKEY_SIZE;

// Declare a static dispatcher object for enabling
// for better organizing enclave-wise global variables
static ecall_dispatcher dispatcher("Enclave1", &config_data);
const char* enclave_name = "Enclave1";
/**
 * Return the public key of this enclave along with the enclave's remote report.
 * Another enclave can use the remote report to attest the enclave and verify
 * the integrity of the public key.
 */
int get_remote_report_with_pubkey(
    uint8_t** pem_key,
    size_t* key_size,
    uint8_t** remote_report,
    size_t* remote_report_size)
{
    TRACE_ENCLAVE("enter get_remote_report_with_pubkey");
    return dispatcher.get_remote_report_with_pubkey(
        pem_key, key_size, remote_report, remote_report_size);
}

// Attest and store the public key of other enclave.
int verify_report_and_set_pubkey(
    uint8_t* pem_key,
    size_t key_size,
    uint8_t* remote_report,
    size_t remote_report_size,
    uint8_t index)
{
    return dispatcher.verify_report_and_set_pubkey(
        pem_key, key_size, remote_report, remote_report_size, index);
}
