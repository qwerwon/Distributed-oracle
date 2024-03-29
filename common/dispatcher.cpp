// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "dispatcher.h"
#include <openenclave/enclave.h>

ecall_dispatcher::ecall_dispatcher(
    const char* name,
    enclave_config_data_t* enclave_config)
    : m_crypto(NULL), m_attestation(NULL)
{
    m_enclave_config = enclave_config;
    m_initialized = initialize(name);
}

ecall_dispatcher::~ecall_dispatcher()
{
    if (m_crypto)
        delete m_crypto;

    if (m_attestation)
        delete m_attestation;
}

bool ecall_dispatcher::initialize(const char* name)
{
    bool ret = false;
    uint8_t* modulus = NULL;
    size_t modulus_size;

    m_name = name;
    m_crypto = new Crypto();
    if (m_crypto == NULL)
    {
        goto exit;
    }

    // Extract modulus from raw PEM.
    for (int i = 0; i < 3; i++){
        if (!m_crypto->get_rsa_modulus_from_pem(
                m_enclave_config->other_enclave_pubkey_pem[i],
                m_enclave_config->other_enclave_pubkey_pem_size,
                &modulus,
                &modulus_size))
        {
            goto exit;
        }

        // Reverse the modulus and compute sha256 on it.
        for (size_t i = 0; i < modulus_size / 2; i++)
        {
            uint8_t tmp = modulus[i];
            modulus[i] = modulus[modulus_size - 1 - i];
            modulus[modulus_size - 1 - i] = tmp;
        }

        // Calculate the MRSIGNER value which is the SHA256 hash of the
        // little endian representation of the public key modulus. This value
        // is populated by the signer_id sub-field of a parsed oe_report_t's
        // identity field.
        if (m_crypto->Sha256(modulus, modulus_size, m_other_enclave_mrsigner[i]) != 0)
        {
            goto exit;
        }

        if (modulus != NULL)
            free(modulus);
    }

    m_attestation = new Attestation(m_crypto, m_other_enclave_mrsigner);
    if (m_attestation == NULL)
    {
        goto exit;
    }
    ret = true;

exit:
    if (modulus != NULL)
        free(modulus);

    return ret;
}

/**
 * Return the public key of this enclave along with the enclave's remote report.
 * The enclave that receives the key will use the remote report to attest this
 * enclave.
 */
int ecall_dispatcher::get_remote_report_with_pubkey(
    uint8_t** pem_key,
    size_t* key_size,
    uint8_t** remote_report,
    size_t* remote_report_size)
{
    uint8_t pem_public_key[512];
    uint8_t* report = NULL;
    size_t report_size = 0;
    uint8_t* key_buf = NULL;
    int ret = 1;

    TRACE_ENCLAVE("get_remote_report_with_pubkey");
    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    m_crypto->retrieve_public_key(pem_public_key);

    // Generate a remote report for the public key so that the enclave that
    // receives the key can attest this enclave.
    if (m_attestation->generate_remote_report(
            pem_public_key, sizeof(pem_public_key), &report, &report_size))
    {
        // Allocate memory on the host and copy the report over.
        *remote_report = (uint8_t*)oe_host_malloc(report_size);
        if (*remote_report == NULL)
        {
            ret = OE_OUT_OF_MEMORY;
            goto exit;
        }
        memcpy(*remote_report, report, report_size);
        *remote_report_size = report_size;
        oe_free_report(report);

        key_buf = (uint8_t*)oe_host_malloc(512);
        if (key_buf == NULL)
        {
            ret = OE_OUT_OF_MEMORY;
            goto exit;
        }
        memcpy(key_buf, pem_public_key, sizeof(pem_public_key));

        *pem_key = key_buf;
        *key_size = sizeof(pem_public_key);

        ret = 0;
        TRACE_ENCLAVE("get_remote_report_with_pubkey succeeded");
    }
    else
    {
        TRACE_ENCLAVE("get_remote_report_with_pubkey failed.");
    }

exit:
    if (ret != 0)
    {
        if (report)
            oe_free_report(report);
        if (key_buf)
            oe_host_free(key_buf);
        if (*remote_report)
            oe_host_free(*remote_report);
    }
    return ret;
}

int ecall_dispatcher::verify_report_and_set_pubkey(
    uint8_t* pem_key,
    size_t key_size,
    uint8_t* remote_report,
    size_t remote_report_size,
    uint8_t index)
{
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    // Attest the remote report and accompanying key.
    if (m_attestation->attest_remote_report(
            remote_report, remote_report_size, pem_key, key_size, index))
    {
        memcpy(m_crypto->get_the_other_enclave_public_key(index), pem_key, key_size);
    }
    else
    {
        TRACE_ENCLAVE("verify_report_and_set_pubkey failed.");
        goto exit;
    }
    ret = 0;
    TRACE_ENCLAVE("verify_report_and_set_pubkey succeeded.");

exit:
    return ret;
}
