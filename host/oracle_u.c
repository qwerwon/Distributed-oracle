/*
 *  This file is auto generated by oeedger8r. DO NOT EDIT.
 */
#include "oracle_u.h"
#include <openenclave/edger8r/host.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

OE_EXTERNC_BEGIN

/* Wrappers for ecalls */

oe_result_t get_remote_report_with_pubkey(
        oe_enclave_t* enclave,
        int* _retval,
        uint8_t** pem_key,
        size_t* key_size,
        uint8_t** remote_report,
        size_t* remote_report_size)
{
    oe_result_t _result = OE_FAILURE;

    /* Marshalling struct */ 
    get_remote_report_with_pubkey_args_t _args, *_pargs_in = NULL, *_pargs_out=NULL;

    /* Marshalling buffer and sizes */ 
    size_t _input_buffer_size = 0;
    size_t _output_buffer_size = 0;
    size_t _total_buffer_size = 0;
    uint8_t* _buffer = NULL;
    uint8_t* _input_buffer = NULL;
    uint8_t* _output_buffer = NULL;
    size_t _input_buffer_offset = 0;
    size_t _output_buffer_offset = 0;
    size_t _output_bytes_written = 0;

    /* Fill marshalling struct */
    memset(&_args, 0, sizeof(_args));
    _args.pem_key = (uint8_t**) pem_key;
    _args.key_size = (size_t*) key_size;
    _args.remote_report = (uint8_t**) remote_report;
    _args.remote_report_size = (size_t*) remote_report_size;

    /* Compute input buffer size. Include in and in-out parameters. */
    OE_ADD_SIZE(_input_buffer_size, sizeof(get_remote_report_with_pubkey_args_t));

    /* Compute output buffer size. Include out and in-out parameters. */
    OE_ADD_SIZE(_output_buffer_size, sizeof(get_remote_report_with_pubkey_args_t));
    if (pem_key) OE_ADD_SIZE(_output_buffer_size, sizeof(uint8_t*));
    if (key_size) OE_ADD_SIZE(_output_buffer_size, sizeof(size_t));
    if (remote_report) OE_ADD_SIZE(_output_buffer_size, sizeof(uint8_t*));
    if (remote_report_size) OE_ADD_SIZE(_output_buffer_size, sizeof(size_t));

    /* Allocate marshalling buffer */
    _total_buffer_size = _input_buffer_size;
    OE_ADD_SIZE(_total_buffer_size, _output_buffer_size);

    _buffer = (uint8_t*) malloc(_total_buffer_size);
    _input_buffer = _buffer;
    _output_buffer = _buffer + _input_buffer_size;
    if (_buffer == NULL) { 
        _result = OE_OUT_OF_MEMORY;
        goto done;
    }

    /* Serialize buffer inputs (in and in-out parameters) */
    *(uint8_t**)&_pargs_in = _input_buffer; 
    OE_ADD_SIZE(_input_buffer_offset, sizeof(*_pargs_in));


    /* Copy args structure (now filled) to input buffer */
    memcpy(_pargs_in, &_args, sizeof(*_pargs_in));

    /* Call enclave function */
    if((_result = oe_call_enclave_function(
                        enclave,
                        fcn_id_get_remote_report_with_pubkey,
                        _input_buffer, _input_buffer_size,
                        _output_buffer, _output_buffer_size,
                         &_output_bytes_written)) != OE_OK)
        goto done;

    /* Set up output arg struct pointer */
    *(uint8_t**)&_pargs_out = _output_buffer; 
    OE_ADD_SIZE(_output_buffer_offset, sizeof(*_pargs_out));

    /* Check if the call succeeded */
    if ((_result=_pargs_out->_result) != OE_OK)
        goto done;

    /* Currently exactly _output_buffer_size bytes must be written */
    if (_output_bytes_written != _output_buffer_size) {
        _result = OE_FAILURE;
        goto done;
    }

    /* Unmarshal return value and out, in-out parameters */
    *_retval = _pargs_out->_retval;
    OE_READ_OUT_PARAM(pem_key, (size_t)(sizeof(uint8_t*)));
    OE_READ_OUT_PARAM(key_size, (size_t)(sizeof(size_t)));
    OE_READ_OUT_PARAM(remote_report, (size_t)(sizeof(uint8_t*)));
    OE_READ_OUT_PARAM(remote_report_size, (size_t)(sizeof(size_t)));

    _result = OE_OK;
done:    
    if (_buffer)
        free(_buffer);
    return _result;
}



oe_result_t verify_report_and_set_pubkey(
        oe_enclave_t* enclave,
        int* _retval,
        uint8_t* pem_key,
        size_t key_size,
        uint8_t* remote_report,
        size_t remote_report_size)
{
    oe_result_t _result = OE_FAILURE;

    /* Marshalling struct */ 
    verify_report_and_set_pubkey_args_t _args, *_pargs_in = NULL, *_pargs_out=NULL;

    /* Marshalling buffer and sizes */ 
    size_t _input_buffer_size = 0;
    size_t _output_buffer_size = 0;
    size_t _total_buffer_size = 0;
    uint8_t* _buffer = NULL;
    uint8_t* _input_buffer = NULL;
    uint8_t* _output_buffer = NULL;
    size_t _input_buffer_offset = 0;
    size_t _output_buffer_offset = 0;
    size_t _output_bytes_written = 0;

    /* Fill marshalling struct */
    memset(&_args, 0, sizeof(_args));
    _args.pem_key = (uint8_t*) pem_key;
    _args.key_size = key_size;
    _args.remote_report = (uint8_t*) remote_report;
    _args.remote_report_size = remote_report_size;

    /* Compute input buffer size. Include in and in-out parameters. */
    OE_ADD_SIZE(_input_buffer_size, sizeof(verify_report_and_set_pubkey_args_t));
    if (pem_key) OE_ADD_SIZE(_input_buffer_size, (_args.key_size * sizeof(uint8_t)));
    if (remote_report) OE_ADD_SIZE(_input_buffer_size, (_args.remote_report_size * sizeof(uint8_t)));

    /* Compute output buffer size. Include out and in-out parameters. */
    OE_ADD_SIZE(_output_buffer_size, sizeof(verify_report_and_set_pubkey_args_t));

    /* Allocate marshalling buffer */
    _total_buffer_size = _input_buffer_size;
    OE_ADD_SIZE(_total_buffer_size, _output_buffer_size);

    _buffer = (uint8_t*) malloc(_total_buffer_size);
    _input_buffer = _buffer;
    _output_buffer = _buffer + _input_buffer_size;
    if (_buffer == NULL) { 
        _result = OE_OUT_OF_MEMORY;
        goto done;
    }

    /* Serialize buffer inputs (in and in-out parameters) */
    *(uint8_t**)&_pargs_in = _input_buffer; 
    OE_ADD_SIZE(_input_buffer_offset, sizeof(*_pargs_in));

    OE_WRITE_IN_PARAM(pem_key, (_args.key_size * sizeof(uint8_t)));
    OE_WRITE_IN_PARAM(remote_report, (_args.remote_report_size * sizeof(uint8_t)));

    /* Copy args structure (now filled) to input buffer */
    memcpy(_pargs_in, &_args, sizeof(*_pargs_in));

    /* Call enclave function */
    if((_result = oe_call_enclave_function(
                        enclave,
                        fcn_id_verify_report_and_set_pubkey,
                        _input_buffer, _input_buffer_size,
                        _output_buffer, _output_buffer_size,
                         &_output_bytes_written)) != OE_OK)
        goto done;

    /* Set up output arg struct pointer */
    *(uint8_t**)&_pargs_out = _output_buffer; 
    OE_ADD_SIZE(_output_buffer_offset, sizeof(*_pargs_out));

    /* Check if the call succeeded */
    if ((_result=_pargs_out->_result) != OE_OK)
        goto done;

    /* Currently exactly _output_buffer_size bytes must be written */
    if (_output_bytes_written != _output_buffer_size) {
        _result = OE_FAILURE;
        goto done;
    }

    /* Unmarshal return value and out, in-out parameters */
    *_retval = _pargs_out->_retval;

    _result = OE_OK;
done:    
    if (_buffer)
        free(_buffer);
    return _result;
}




/*ocall function table*/
static oe_ocall_func_t __oracle_ocall_function_table[]= {
    NULL
};

oe_result_t oe_create_oracle_enclave(const char* path,
                                 oe_enclave_type_t type,
                                 uint32_t flags,
                                 const void* config,
                                 uint32_t config_size,
                                 oe_enclave_t** enclave)
{
    return oe_create_enclave(path,
               type,
               flags,
               config,
               config_size,
               __oracle_ocall_function_table,
               0,
               enclave);
}

OE_EXTERNC_END
