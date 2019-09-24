// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// Copyright (c) Express Logic.  All rights reserved.
// Please contact support@expresslogic.com for any questions or use the support portal at www.rtos.com


/* This file is used for porting tlsio between x-ware and azure-iot-sdk-c.  */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "nx_api.h"
#include "nx_secure_tls_api.h"
#include "certs_xware.c"
#include "azure_c_shared_utility/optimize_size.h"
#include "azure_c_shared_utility/tlsio.h"
#include "azure_c_shared_utility/socketio.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/shared_util_options.h"

#define OPTION_UNDERLYING_IO_OPTIONS        "underlying_io_options"


/* Define the default metadata, remote certificate, packet buffer, etc.  The user can override this 
   via -D command line option or via project settings.  */

/* Define the metadata size for XWARE TLS.  */
#ifndef XWARE_TLS_METADATA_BUFFER
#define XWARE_TLS_METADATA_BUFFER           (16 * 1024)
#endif /* XWARE_TLS_METADATA_BUFFER  */

/* Define the remote certificate count for XWARE TLS.  */
#ifndef XWARE_TLS_REMOTE_CERTIFICATE_COUNT
#define XWARE_TLS_REMOTE_CERTIFICATE_COUNT  2
#endif /* XWARE_TLS_REMOTE_CERTIFICATE_COUNT  */

/* Define the remote certificate buffer for XWARE TLS.  */
#ifndef XWARE_TLS_REMOTE_CERTIFICATE_BUFFER
#define XWARE_TLS_REMOTE_CERTIFICATE_BUFFER 4096
#endif /* XWARE_TLS_REMOTE_CERTIFICATE_BUFFER  */

/* Define the packet buffer for XWARE TLS.  */
#ifndef XWARE_TLS_PACKET_BUFFER
#define XWARE_TLS_PACKET_BUFFER             4096
#endif /* XWARE_TLS_PACKET_BUFFER  */

UCHAR xware_tls_metadata_buffer[XWARE_TLS_METADATA_BUFFER];
NX_SECURE_X509_CERT xware_tls_remote_certificate[XWARE_TLS_REMOTE_CERTIFICATE_COUNT];
UCHAR xware_tls_remote_cert_buffer[XWARE_TLS_REMOTE_CERTIFICATE_COUNT][XWARE_TLS_REMOTE_CERTIFICATE_BUFFER];
UCHAR xware_tls_packet_buffer[XWARE_TLS_PACKET_BUFFER];

/* Use the default ciphers from nx_secure/nx_crypto_generic_ciphersuites.c  */
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

extern NX_TCP_SOCKET *_xware_tcp_socket_created_ptr;    /* X-WARE TCP Socket.  */


typedef enum TLSIO_STATE_ENUM_TAG
{
    TLSIO_STATE_NOT_OPEN,
    TLSIO_STATE_OPENING_UNDERLYING_IO,
    TLSIO_STATE_IN_HANDSHAKE,
    TLSIO_STATE_OPEN,
    TLSIO_STATE_CLOSING,
    TLSIO_STATE_ERROR
} TLSIO_STATE_ENUM;

typedef struct TLS_IO_INSTANCE_TAG
{
    XIO_HANDLE socket_io;
    ON_BYTES_RECEIVED on_bytes_received;
    ON_IO_OPEN_COMPLETE on_io_open_complete;
    ON_IO_CLOSE_COMPLETE on_io_close_complete;
    ON_IO_ERROR on_io_error;
    void* on_bytes_received_context;
    void* on_io_open_complete_context;
    void* on_io_close_complete_context;
    void* on_io_error_context;
    TLSIO_STATE_ENUM tlsio_state;
    unsigned char* socket_io_read_bytes;
    size_t socket_io_read_byte_count;
    ON_SEND_COMPLETE on_send_complete;
    void* on_send_complete_callback_context;
    char*                      trusted_certificates;
    NX_SECURE_X509_CERT        xware_tls_certificate;
    NX_SECURE_X509_CERT        xware_tls_trusted_certificate;
    NX_SECURE_TLS_SESSION      xware_tls_session;
    NX_TCP_SOCKET              *xware_tcp_socket;
} TLS_IO_INSTANCE;

static void indicate_error(TLS_IO_INSTANCE* tls_io_instance)
{
    if (tls_io_instance->on_io_error != NULL)
    {
        tls_io_instance->on_io_error(tls_io_instance->on_io_error_context);
    }
}

static void indicate_open_complete(TLS_IO_INSTANCE* tls_io_instance, IO_OPEN_RESULT open_result)
{
    if (tls_io_instance->on_io_open_complete != NULL)
    {
        tls_io_instance->on_io_open_complete(tls_io_instance->on_io_open_complete_context, open_result);
    }
}

static void xware_tls_received_bytes(TLS_IO_INSTANCE* tls_io_instance)
{

UINT    status = NX_SUCCESS;
NX_PACKET *my_packet;
NX_PACKET *release_packet;

    /* X-WARE receive tcp data.  */
    status = NX_SUCCESS;
    while ((status == NX_SUCCESS) && (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN))
    {

        /* Receive the data.  */
        status = nx_secure_tls_session_receive(&(tls_io_instance -> xware_tls_session), &my_packet, NX_NO_WAIT);

        /* Check status.  */
        if (status == NX_SUCCESS)
        {
                
            release_packet = my_packet;
            if (tls_io_instance->on_bytes_received != NULL)
            {

                ULONG  received;
#ifndef NX_DISABLE_PACKET_CHAIN
                /* Loop to copy bytes from packet(s).  */
                while (my_packet)
                {
#endif /* NX_DISABLE_PACKET_CHAIN */

                    /* Calculate the bytes to copy in this packet. */
                    /*lint -e{946} -e{947} suppress pointer subtraction, since it is necessary. */
                    received = (ULONG)(my_packet -> nx_packet_append_ptr - my_packet -> nx_packet_prepend_ptr);

                    /* explictly ignoring here the result of the callback */
                    (void)tls_io_instance->on_bytes_received(tls_io_instance->on_bytes_received_context, my_packet -> nx_packet_prepend_ptr, received);
#ifndef NX_DISABLE_PACKET_CHAIN
                    /* Move to next packet.  */
                    my_packet =  my_packet -> nx_packet_next;
                }
#endif /* NX_DISABLE_PACKET_CHAIN */
            }

            /* Release the packet.  */
            nx_packet_release(release_packet);
        }
    }
}

static void on_underlying_io_open_complete(void* context, IO_OPEN_RESULT open_result)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;
    int result = 0;

    if (open_result != IO_OPEN_OK)
    {
        xio_close(tls_io_instance->socket_io, NULL, NULL);
        tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
        indicate_open_complete(tls_io_instance, IO_OPEN_ERROR);
    }
    else
    {
        tls_io_instance->tlsio_state = TLSIO_STATE_IN_HANDSHAKE;

        /* Start X-WARE TLS session.  */
        tls_io_instance -> xware_tcp_socket = _xware_tcp_socket_created_ptr;
        result = nx_secure_tls_session_start(&(tls_io_instance -> xware_tls_session), tls_io_instance -> xware_tcp_socket, NX_WAIT_FOREVER);

        if (result == 0)
        {
            tls_io_instance->tlsio_state = TLSIO_STATE_OPEN;
            indicate_open_complete(tls_io_instance, IO_OPEN_OK);
        }
        else
        {
            xio_close(tls_io_instance->socket_io, NULL, NULL);
            tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
            indicate_open_complete(tls_io_instance, IO_OPEN_ERROR);
        }
    }
}

static void on_underlying_io_bytes_received(void* context, const unsigned char* buffer, size_t size)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;

    unsigned char* new_socket_io_read_bytes = (unsigned char*)realloc(tls_io_instance->socket_io_read_bytes, tls_io_instance->socket_io_read_byte_count + size);

    if (new_socket_io_read_bytes == NULL)
    {
        tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
        indicate_error(tls_io_instance);
    }
    else
    {
        tls_io_instance->socket_io_read_bytes = new_socket_io_read_bytes;
        (void)memcpy(tls_io_instance->socket_io_read_bytes + tls_io_instance->socket_io_read_byte_count, buffer, size);
        tls_io_instance->socket_io_read_byte_count += size;
    }
}

static void on_underlying_io_error(void* context)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;

    switch (tls_io_instance->tlsio_state)
    {
    default:
    case TLSIO_STATE_NOT_OPEN:
    case TLSIO_STATE_ERROR:
        break;

    case TLSIO_STATE_OPENING_UNDERLYING_IO:
    case TLSIO_STATE_IN_HANDSHAKE:
        // Existing socket impls are all synchronous close, and this 
        // adapter does not yet support async close.
        xio_close(tls_io_instance->socket_io, NULL, NULL);
        tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
        indicate_open_complete(tls_io_instance, IO_OPEN_ERROR);
        break;

    case TLSIO_STATE_OPEN:
        tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
        indicate_error(tls_io_instance);
        break;
    }
}

static void on_underlying_io_close_complete(void* context)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;

    tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;

    if (tls_io_instance->on_io_close_complete != NULL)
    {
        tls_io_instance->on_io_close_complete(tls_io_instance->on_io_close_complete_context);
    }
}

static void xware_tls_init(void *instance)
{

    TLS_IO_INSTANCE *result = (TLS_IO_INSTANCE *)instance;
    UINT i;

    /* X-WARE TLS setup.  */
    nx_secure_tls_session_create(&(result -> xware_tls_session),
                                 &nx_crypto_tls_ciphers,
                                 xware_tls_metadata_buffer,
                                 sizeof(xware_tls_metadata_buffer));

    for (i = 0; i < sizeof(xware_tls_remote_certificate) / sizeof(NX_SECURE_X509_CERT); i++)
    {

        /* Need to allocate space for the certificate coming in from the remote host. */
        nx_secure_tls_remote_certificate_allocate(&(result -> xware_tls_session), &xware_tls_remote_certificate[i],
                                                  xware_tls_remote_cert_buffer[i], sizeof(xware_tls_remote_cert_buffer[i]));
    }

    /* Add a CA Certificate to our trusted store for verifying incoming server certificates. */
    nx_secure_x509_certificate_initialize(&(result -> xware_tls_trusted_certificate), xware_tls_root_ca_cert,
                                          sizeof(xware_tls_root_ca_cert), NX_NULL, 0, NULL, 0,
                                          NX_SECURE_X509_KEY_TYPE_NONE);
    nx_secure_tls_trusted_certificate_add(&(result -> xware_tls_session), &(result -> xware_tls_trusted_certificate));

    nx_secure_tls_session_packet_buffer_set(&(result -> xware_tls_session), xware_tls_packet_buffer, sizeof(xware_tls_packet_buffer));
}

CONCRETE_IO_HANDLE tlsio_xware_tls_create(void* io_create_parameters)
{
    TLSIO_CONFIG* tls_io_config = io_create_parameters;

    TLS_IO_INSTANCE* result;
         
    if (tls_io_config == NULL)
    {
        LogError("NULL tls_io_config");
        result = NULL;
    }
    else
    {
        result = malloc(sizeof(TLS_IO_INSTANCE));
        if (result == NULL)
        {
            LogError("malloc failed");
        }
        else
        {

            (void)memset(result, 0, sizeof(TLS_IO_INSTANCE));

            SOCKETIO_CONFIG socketio_config;
            const IO_INTERFACE_DESCRIPTION* underlying_io_interface;
            void* io_interface_parameters;

            if (tls_io_config->underlying_io_interface != NULL)
            {
                underlying_io_interface = tls_io_config->underlying_io_interface;
                io_interface_parameters = tls_io_config->underlying_io_parameters;
            }
            else
            {
                socketio_config.hostname = tls_io_config->hostname;
                socketio_config.port = tls_io_config->port;
                socketio_config.accepted_socket = NULL;

                underlying_io_interface = socketio_get_interface_description();
                io_interface_parameters = &socketio_config;
            }

            if (underlying_io_interface == NULL)
            {
                free(result);
                result = NULL;
                LogError("Failed getting socket IO interface description.");
            }
            else
            {
                result->on_bytes_received = NULL;
                result->on_bytes_received_context = NULL;

                result->on_io_open_complete = NULL;
                result->on_io_open_complete_context = NULL;

                result->on_io_close_complete = NULL;
                result->on_io_close_complete_context = NULL;

                result->on_io_error = NULL;
                result->on_io_error_context = NULL;

                result->trusted_certificates = NULL;

                result->socket_io = xio_create(underlying_io_interface, io_interface_parameters);
                if (result->socket_io == NULL)
                {
                    LogError("socket xio create failed");
                    free(result);
                    result = NULL;
                }
                else
                {
                    result->socket_io_read_bytes = NULL;
                    result->socket_io_read_byte_count = 0;
                    result->on_send_complete = NULL;
                    result->on_send_complete_callback_context = NULL;

                    /* X-WARE TLS initialize.  */
                    xware_tls_init((void *)result);
                    result->tlsio_state = TLSIO_STATE_NOT_OPEN;
                }
            }
        }
    }

    return (result);
}

void tlsio_xware_tls_destroy(CONCRETE_IO_HANDLE tls_io)
{

    if (tls_io != NULL)
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        /* Delete X-WARE TLS.  */
        nx_secure_tls_session_delete(&(tls_io_instance -> xware_tls_session));

        xio_close(tls_io_instance->socket_io, NULL, NULL);
        xio_destroy(tls_io_instance->socket_io);

        free(tls_io);
    }
}

int tlsio_xware_tls_open(CONCRETE_IO_HANDLE tls_io, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context, ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context, ON_IO_ERROR on_io_error, void* on_io_error_context)
{

    int result = 0;

    if (tls_io == NULL)
    {
        LogError("NULL tls_io");
        result = MU_FAILURE;
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        if (tls_io_instance->tlsio_state != TLSIO_STATE_NOT_OPEN)
        {
            LogError("IO should not be open: %d\n", tls_io_instance->tlsio_state);
            result = MU_FAILURE;
        }
        else
        {
            tls_io_instance->on_bytes_received = on_bytes_received;
            tls_io_instance->on_bytes_received_context = on_bytes_received_context;

            tls_io_instance->on_io_open_complete = on_io_open_complete;
            tls_io_instance->on_io_open_complete_context = on_io_open_complete_context;

            tls_io_instance->on_io_error = on_io_error;
            tls_io_instance->on_io_error_context = on_io_error_context;

            tls_io_instance->tlsio_state = TLSIO_STATE_OPENING_UNDERLYING_IO;

            if (xio_open(tls_io_instance->socket_io, on_underlying_io_open_complete, tls_io_instance, on_underlying_io_bytes_received, tls_io_instance, on_underlying_io_error, tls_io_instance) != 0)
            {
                LogError("Underlying IO open failed");
                tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
                result = MU_FAILURE;
            }
            else
            {
                result = 0;
            }
        }
    }

    return (result);
}

int tlsio_xware_tls_close(CONCRETE_IO_HANDLE tls_io, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
{
    int result;

    if (tls_io == NULL)
    {
        result = MU_FAILURE;
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        if ((tls_io_instance->tlsio_state == TLSIO_STATE_NOT_OPEN) ||
            (tls_io_instance->tlsio_state == TLSIO_STATE_CLOSING))
        {
            result = MU_FAILURE;
        }
        else
        {
            tls_io_instance->tlsio_state = TLSIO_STATE_CLOSING;
            tls_io_instance->on_io_close_complete = on_io_close_complete;
            tls_io_instance->on_io_close_complete_context = callback_context;

            /* Close X-WARE TLS close.  */
            nx_secure_tls_session_end(&(tls_io_instance -> xware_tls_session), NX_NO_WAIT);
            xio_close(tls_io_instance->socket_io, on_underlying_io_close_complete, tls_io_instance);

            result = 0;
        }
    }

    return result;
}

int tlsio_xware_tls_send(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{

    int result;

    if (tls_io == NULL || (buffer == NULL) || (size == 0))
    {
        LogError("Invalid parameter specified tls_io: %p, buffer: %p, size: %ul", tls_io, buffer, (unsigned int)size);
        result = MU_FAILURE;
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        if (tls_io_instance->tlsio_state != TLSIO_STATE_OPEN)
        {
            result = MU_FAILURE;
        }
        else
        {
            tls_io_instance->on_send_complete = on_send_complete;
            tls_io_instance->on_send_complete_callback_context = callback_context;

            /* X-WARE send tcp data.  */
            UINT status;
            NX_PACKET *my_packet;
            UINT buffer_index = 0;
            UINT packet_available_size;

            while(size > 0)
            {

                /* Allocate packet.  */
                status = nx_secure_tls_packet_allocate(&(tls_io_instance -> xware_tls_session), (tls_io_instance -> xware_tls_session).nx_secure_tls_packet_pool, &my_packet, NX_NO_WAIT);

                /* Check status.  */
                if (status)
                {
                    break;
                }
                else
                {

                    /* Compute the available size for packet.  */
                    packet_available_size = (my_packet -> nx_packet_data_end - my_packet -> nx_packet_append_ptr);

                    /* Check if the packet can fill all data.  */
                    if (size < packet_available_size)
                        packet_available_size = size;

                    /* Fill the message.  */
                    memcpy(my_packet -> nx_packet_append_ptr, (UCHAR *)buffer + buffer_index, packet_available_size);
                    my_packet -> nx_packet_length = packet_available_size;
                    my_packet -> nx_packet_append_ptr += my_packet -> nx_packet_length;

                    /* Send out the packet.  */
                    status = nx_secure_tls_session_send(&(tls_io_instance -> xware_tls_session), my_packet, NX_NO_WAIT);

                    /* Check status.  */
                    if (status)
                    {

                        /* Release the packet.  */
                        nx_packet_release(my_packet);
                        break;
                    }
                    else
                    {

                        /* Update the send result.  */
                        size -= packet_available_size;
                        buffer_index += packet_available_size;
                    }
                }
            }

            if (size)
            {
                result = MU_FAILURE;
            }
            else
            {
                result = 0;
            }
        }
    }

    return (result);
}

void tlsio_xware_tls_dowork(CONCRETE_IO_HANDLE tls_io)
{

    if (tls_io != NULL)
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        if ((tls_io_instance->tlsio_state != TLSIO_STATE_NOT_OPEN) &&
            (tls_io_instance->tlsio_state != TLSIO_STATE_ERROR))
        {

            xware_tls_received_bytes(tls_io_instance);

            xio_dowork(tls_io_instance->socket_io);
        }
    }
}

/*this function will clone an option given by name and value*/
static void* tlsio_xware_tls_cloneoption(const char* name, const void* value)
{
    void* result;
    if (
        (name == NULL) || (value == NULL)
        )
    {
        LogError("invalid parameter detected: const char* name=%p, const void* value=%p", name, value);
        result = NULL;
    }
    else
    {
        if (strcmp(name, OPTION_UNDERLYING_IO_OPTIONS) == 0)
        {
            result = (void*)value;
        }
        else if (strcmp(name, OPTION_TRUSTED_CERT) == 0)
        {
            if (mallocAndStrcpy_s((char**)&result, value) != 0)
            {
                LogError("unable to mallocAndStrcpy_s TrustedCerts value");
                result = NULL;
            }
            else
            {
                /*return as is*/
            }
        }
        else
        {
            LogError("not handled option : %s", name);
            result = NULL;
        }
    }
    return result;
}

/*this function destroys an option previously created*/
static void tlsio_xware_tls_destroyoption(const char* name, const void* value)
{
    /*since all options for this layer are actually string copies., disposing of one is just calling free*/
    if (name == NULL || value == NULL)
    {
        LogError("invalid parameter detected: const char* name=%p, const void* value=%p", name, value);
    }
    else
    {
        if (strcmp(name, OPTION_TRUSTED_CERT) == 0)
        {
            free((void*)value);
        }
        else if (strcmp(name, OPTION_UNDERLYING_IO_OPTIONS) == 0)
        {
            OptionHandler_Destroy((OPTIONHANDLER_HANDLE)value);
        }
        else
        {
            LogError("not handled option : %s", name);
        }
    }
}

int tlsio_xware_tls_setoption(CONCRETE_IO_HANDLE tls_io, const char* optionName, const void* value)
{
    int result;

    if (tls_io == NULL || optionName == NULL)
    {
        result = MU_FAILURE;
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        if (strcmp(OPTION_TRUSTED_CERT, optionName) == 0)
        {
            if (tls_io_instance->trusted_certificates != NULL)
            {
                // Free the memory if it has been previously allocated
                free(tls_io_instance->trusted_certificates);
                tls_io_instance->trusted_certificates = NULL;
            }
            if (mallocAndStrcpy_s(&tls_io_instance->trusted_certificates, (const char*)value) != 0)
            {
                LogError("unable to mallocAndStrcpy_s");
                result = MU_FAILURE;
            }
            else
            {          
                result = 0;
            }
        }
        else
        {
            // tls_io_instance->socket_io is never NULL
            result = xio_setoption(tls_io_instance->socket_io, optionName, value);
        }
    }

    return result;
}

OPTIONHANDLER_HANDLE tlsio_xware_tls_retrieveoptions(CONCRETE_IO_HANDLE handle)
{
    OPTIONHANDLER_HANDLE result;
    if (handle == NULL)
    {
        LogError("invalid parameter detected: CONCRETE_IO_HANDLE handle=%p", handle);
        result = NULL;
    }
    else
    {
        result = OptionHandler_Create(tlsio_xware_tls_cloneoption, tlsio_xware_tls_destroyoption, tlsio_xware_tls_setoption);
        if (result == NULL)
        {
            LogError("unable to OptionHandler_Create");
            /*return as is*/
        }
        else
        {
            /*this layer cares about the certificates*/
            TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)handle;
            OPTIONHANDLER_HANDLE underlying_io_options;

            if ((underlying_io_options = xio_retrieveoptions(tls_io_instance->socket_io)) == NULL ||
                OptionHandler_AddOption(result, OPTION_UNDERLYING_IO_OPTIONS, underlying_io_options) != OPTIONHANDLER_OK)
            {
                LogError("unable to save underlying_io options");
                OptionHandler_Destroy(underlying_io_options);
                OptionHandler_Destroy(result);
                result = NULL;
            }
            else if (tls_io_instance->trusted_certificates != NULL &&
                OptionHandler_AddOption(result, OPTION_TRUSTED_CERT, tls_io_instance->trusted_certificates) != OPTIONHANDLER_OK)
            {
                LogError("unable to save TrustedCerts option");
                OptionHandler_Destroy(result);
                result = NULL;
            }
            else
            {
                /*all is fine, all interesting options have been saved*/
                /*return as is*/
            }
        }
    }
    return result;
}

static const IO_INTERFACE_DESCRIPTION tlsio_xware_tls_interface_description =
{
    tlsio_xware_tls_retrieveoptions,
    tlsio_xware_tls_create,
    tlsio_xware_tls_destroy,
    tlsio_xware_tls_open,
    tlsio_xware_tls_close,
    tlsio_xware_tls_send,
    tlsio_xware_tls_dowork,
    tlsio_xware_tls_setoption
};

const IO_INTERFACE_DESCRIPTION* tlsio_xware_tls_get_interface_description(void)
{
    return &tlsio_xware_tls_interface_description;
}
