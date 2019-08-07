// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// Copyright (c) Express Logic.  All rights reserved.
// Please contact support@expresslogic.com for any questions or use the support portal at www.rtos.com


/* This file is used for porting mqtt between x-ware and azure-iot-sdk-c.  */

#include <stdlib.h>
#include "azure_c_shared_utility/optimize_size.h"
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/platform.h"
#include "azure_c_shared_utility/tickcounter.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/strings.h"
#include "azure_c_shared_utility/agenttime.h"
#include "azure_c_shared_utility/threadapi.h"

#include "nx_api.h"
#include "nx_ip.h"
#include "nxd_mqtt_client.h"
#include "nxd_dns.h"
#include "config_xware.h"
#include "mqtt_xware.h"
#include "config_xware.h"
#include <inttypes.h>


/* Define stack size, memory, topic, message for XWARE MQTT.  */
static UCHAR xware_mqtt_client_stack[XWARE_MQTT_CLIENT_STACK_SIZE];
static UCHAR xware_mqtt_client_memory[XWARE_MQTT_CLIENT_MEMORY];
static UCHAR xware_mqtt_client_topic[XWARE_MQTT_CLIENT_TOPIC_SIZE];
static UCHAR xware_mqtt_client_message[XWARE_MQTT_CLIENT_MESSAGE_SIZE];

UINT _nxd_mqtt_read_remaining_length(NX_PACKET *packet_ptr, UINT *remaining_length, UCHAR **variable_header);

extern int xware_host_address_get(NXD_ADDRESS *host_address, const char* host_name);

extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

extern UCHAR xware_tls_metadata_buffer[XWARE_TLS_METADATA_BUFFER];
extern NX_SECURE_X509_CERT xware_tls_remote_certificate[XWARE_TLS_REMOTE_CERTIFICATE_COUNT];
extern UCHAR xware_tls_remote_cert_buffer[XWARE_TLS_REMOTE_CERTIFICATE_BUFFER][XWARE_TLS_REMOTE_CERTIFICATE_BUFFER];
extern UCHAR xware_tls_packet_buffer[XWARE_TLS_PACKET_BUFFER];
extern UCHAR xware_tls_ca_cert_der[];
extern USHORT xware_tls_ca_cert_der_size;
extern void xware_tls_ca_size_get();
  
typedef struct MQTT_CLIENT_TAG
{
    NXD_MQTT_CLIENT  xware_mqtt_client;
    char*            xware_mqtt_username;
    char*            xware_mqtt_password;
    char*            xware_mqtt_client_id;
    NXD_ADDRESS      xware_mqtt_host_address;
    CONTROL_PACKET_TYPE packetState;
    ON_MQTT_OPERATION_CALLBACK fnOperationCallback;
    ON_MQTT_MESSAGE_RECV_CALLBACK fnMessageRecv;
    void* ctx;
    ON_MQTT_ERROR_CALLBACK fnOnErrorCallBack;
    void* errorCBCtx;
    ON_MQTT_DISCONNECTED_CALLBACK disconnect_cb;
    void* disconnect_ctx; 
    QOS_VALUE qosValue;
    uint16_t keepAliveInterval;
    bool clientConnected;
    bool logTrace;
    bool rawBytesTrace;
} MQTT_CLIENT;


static UINT packet_receive_callback(struct NXD_MQTT_CLIENT_STRUCT *client_ptr, NX_PACKET *packet_ptr, VOID *context)
{
    MQTT_CLIENT* mqtt_client = (MQTT_CLIENT*)context;
    UCHAR        packet_type; 
    USHORT       packet_id;
    if ((mqtt_client != NULL) && (packet_ptr != NULL))
    {

        /* Get the packet type.  Right shift 4 bits to get the packet type. */
        packet_type = (*(packet_ptr -> nx_packet_prepend_ptr)) >> 4;

        /* Check the packet type.  */
        switch (packet_type)
        {
            case MQTT_CONTROL_PACKET_TYPE_PUBACK:
            case MQTT_CONTROL_PACKET_TYPE_PUBREC:
            case MQTT_CONTROL_PACKET_TYPE_PUBCOMP:
            case MQTT_CONTROL_PACKET_TYPE_PUBREL:
            {
                if (mqtt_client->fnOperationCallback)
                {
                    MQTT_CLIENT_EVENT_RESULT action;
                    if (packet_type == MQTT_CONTROL_PACKET_TYPE_PUBACK)
                        action = MQTT_CLIENT_ON_PUBLISH_ACK;
                    else if (packet_type == MQTT_CONTROL_PACKET_TYPE_PUBREC)
                        action = MQTT_CLIENT_ON_PUBLISH_RECV;
                    else if (packet_type == MQTT_CONTROL_PACKET_TYPE_PUBCOMP)
                        action = MQTT_CLIENT_ON_PUBLISH_COMP;
                    else
                        action = MQTT_CLIENT_ON_PUBLISH_REL;
                                       
                    MQTT_PACKET_PUBLISH_RESPONSE *publish_response_ptr;
                    publish_response_ptr = (MQTT_PACKET_PUBLISH_RESPONSE *)(packet_ptr -> nx_packet_prepend_ptr);

                    /* Validate the packet. */
                    if (publish_response_ptr -> mqtt_publish_response_packet_remaining_length != 2)
                        break;

                    packet_id = (USHORT)((publish_response_ptr -> mqtt_publish_response_packet_packet_identifier_msb << 8) |
                                            (publish_response_ptr -> mqtt_publish_response_packet_packet_identifier_lsb));
                    PUBLISH_ACK publish_ack = { 0 };
                    publish_ack.packetId = packet_id;

                    mqtt_client->fnOperationCallback(mqtt_client, action, (void*)&publish_ack, mqtt_client->ctx);
                }
                break;
            }
            case MQTT_CONTROL_PACKET_TYPE_SUBACK:
            {
                if (mqtt_client->fnOperationCallback)
                {
                    UCHAR                        *data;

                    /*Codes_SRS_MQTT_CLIENT_07_030: [If the actionResult parameter is of type SUBACK_TYPE then the msgInfo value shall be a SUBSCRIBE_ACK structure.]*/
                    SUBSCRIBE_ACK suback = { 0 };
                                          
                    /* Skip the remaining length field. */
                    if (_nxd_mqtt_read_remaining_length(packet_ptr, NX_NULL, &data))
                    {
                        break;
                    }
                    packet_id = (USHORT)(((*data) << 8) | (*(data + 1)));
                    suback.packetId = packet_id;

                    mqtt_client->fnOperationCallback(mqtt_client, MQTT_CLIENT_ON_SUBSCRIBE_ACK, (void*)&suback, mqtt_client->ctx);
                }
                break;
            }
            case MQTT_CONTROL_PACKET_TYPE_UNSUBACK:
            {
                if (mqtt_client->fnOperationCallback)
                {

                    UCHAR                        *data;

                    /*Codes_SRS_MQTT_CLIENT_07_031: [If the actionResult parameter is of type UNSUBACK_TYPE then the msgInfo value shall be a UNSUBSCRIBE_ACK structure.]*/
                    UNSUBSCRIBE_ACK unsuback = { 0 };
                                          
                    /* Skip the remaining length field. */
                    if (_nxd_mqtt_read_remaining_length(packet_ptr, NX_NULL, &data))
                    {
                        break;
                    }
                    packet_id = (USHORT)(((*data) << 8) | (*(data + 1)));
                    unsuback.packetId = packet_id;

                    mqtt_client->fnOperationCallback(mqtt_client, MQTT_CLIENT_ON_UNSUBSCRIBE_ACK, (void*)&unsuback, mqtt_client->ctx);
                }
                break;
            }  
            case MQTT_CONTROL_PACKET_TYPE_DISCONNECT:
            {

                mqtt_client->clientConnected = false;
                if (mqtt_client->disconnect_cb)
                {
                    mqtt_client->disconnect_cb(mqtt_client->disconnect_ctx);
                }
                break;
            }
            default:
                break;
        }
    }
    return (NX_FALSE);
}

MQTT_CLIENT_HANDLE xware_mqtt_client_init(const IOTHUB_CLIENT_CONFIG* upperConfig, ON_MQTT_MESSAGE_RECV_CALLBACK msgRecv, ON_MQTT_OPERATION_CALLBACK opCallback, void* opCallbackCtx, ON_MQTT_ERROR_CALLBACK onErrorCallBack, void* errorCBCtx)
{
    MQTT_CLIENT* result;

    result = malloc(sizeof(MQTT_CLIENT));
    if (result == NULL)
    {
        /*Codes_SRS_MQTT_CLIENT_07_002: [If any failure is encountered then mqttclient_init shall return NULL.]*/
        LOG(AZ_LOG_ERROR, LOG_LINE, "mqtt_client_init failure: Allocation Failure");
    }
    else
    {
        memset(result, 0, sizeof(MQTT_CLIENT));
        /*Codes_SRS_MQTT_CLIENT_07_003: [mqttclient_init shall allocate MQTTCLIENT_DATA_INSTANCE and return the MQTTCLIENT_HANDLE on success.]*/
        result->packetState = UNKNOWN_TYPE;
        result->fnOperationCallback = opCallback;
        result->ctx = opCallbackCtx;
        result->fnMessageRecv = msgRecv;
        result->fnOnErrorCallBack = onErrorCallBack;
        result->errorCBCtx = errorCBCtx;
        result->qosValue = DELIVER_AT_MOST_ONCE;

        UINT status;

        result -> xware_mqtt_client_id = (char*)malloc(strlen(upperConfig ->deviceId) + 1);
        if (result -> xware_mqtt_client_id == NULL)
        {                 
            free(result);
            result = NULL;
        }
        else
        {
            strcpy(result -> xware_mqtt_client_id, upperConfig ->deviceId);

            /* Create XWARE mqtt.  */
            status = nxd_mqtt_client_create(&(result -> xware_mqtt_client), "XWARE MQTT", result -> xware_mqtt_client_id,
                                            strlen(result -> xware_mqtt_client_id), _nx_ip_created_ptr, _nx_ip_created_ptr -> nx_ip_default_packet_pool,
                                            (VOID*)xware_mqtt_client_stack, XWARE_MQTT_CLIENT_STACK_SIZE,
                                            XWARE_MQTT_CLIENT_PRIORITY,
                                            (UCHAR*)xware_mqtt_client_memory, XWARE_MQTT_CLIENT_MEMORY);
                
            /* Check status.  */
            if (status)
            {
                /*Codes_SRS_MQTT_CLIENT_07_002: [If any failure is encountered then mqttclient_init shall return NULL.]*/
                LOG(AZ_LOG_ERROR, LOG_LINE, "mqtt_client_init failure: mqtt_codec_create failure");
                free(result -> xware_mqtt_client_id);
                free(result);
                result = NULL;
            }

            /* Set the packet receive callback function.  */
            result -> xware_mqtt_client.nxd_mqtt_packet_receive_notify = packet_receive_callback;
            result -> xware_mqtt_client.nxd_mqtt_packet_receive_context = result;
        }
    }

    return result;
}

void xware_mqtt_client_deinit(MQTT_CLIENT_HANDLE handle)
{
    /*Codes_SRS_MQTT_CLIENT_07_004: [If the parameter handle is NULL then function mqtt_client_deinit shall do nothing.]*/
    if (handle != NULL)
    {
        /*Codes_SRS_MQTT_CLIENT_07_005: [mqtt_client_deinit shall deallocate all memory allocated in this unit.]*/
        MQTT_CLIENT* mqtt_client = (MQTT_CLIENT*)handle;
        nxd_mqtt_client_delete(&(mqtt_client -> xware_mqtt_client));
        free(mqtt_client -> xware_mqtt_username);
        free(mqtt_client -> xware_mqtt_password);
        free(mqtt_client -> xware_mqtt_client_id);
        free(mqtt_client); 
    }
}

static void xware_mqtt_tls_init(NX_SECURE_TLS_SESSION *xware_tls_session)
{

    /* X-WARE TLS initialize... */
    nx_secure_tls_initialize();

    /* X-WARE TLS setup.  */
    nx_secure_tls_session_create(xware_tls_session,
                                 &nx_crypto_tls_ciphers,
                                 xware_tls_metadata_buffer,
                                 XWARE_TLS_METADATA_BUFFER);
}

static UINT xware_mqtt_tls_setup(NXD_MQTT_CLIENT *client_ptr, NX_SECURE_TLS_SESSION *tls_session,
               NX_SECURE_X509_CERT *certificate, NX_SECURE_X509_CERT *trusted_certificate)
{
UINT i;

    for (i = 0; i < sizeof(xware_tls_remote_certificate) / sizeof(NX_SECURE_X509_CERT); i++)
    {

        /* Need to allocate space for the certificate coming in from the remote host. */
        nx_secure_tls_remote_certificate_allocate(tls_session, &xware_tls_remote_certificate[i],
                                                  xware_tls_remote_cert_buffer[i], sizeof(xware_tls_remote_cert_buffer[i]));
    }

    xware_tls_ca_size_get();
    /* Add a CA Certificate to our trusted store for verifying incoming server certificates. */
    nx_secure_x509_certificate_initialize(trusted_certificate, xware_tls_ca_cert_der,
                                          xware_tls_ca_cert_der_size, NX_NULL, 0, NULL, 0,
                                          NX_SECURE_X509_KEY_TYPE_NONE);
    nx_secure_tls_trusted_certificate_add(tls_session, trusted_certificate);

    nx_secure_tls_session_packet_buffer_set(tls_session, xware_tls_packet_buffer, sizeof(xware_tls_packet_buffer));
	
	return(NX_SUCCESS);
}

int xware_mqtt_client_connect(MQTT_CLIENT_HANDLE handle, const char* host_name, const char* username, char* password)
{
    int result;

    /*SRS_MQTT_CLIENT_07_006: [If any of the parameters handle, ioHandle, or mqttOptions are NULL then mqtt_client_connect shall return a non-zero value.]*/
    if (handle == NULL)
    {
        LOG(AZ_LOG_ERROR, LOG_LINE, "mqtt_client_connect: NULL argument (handle = %p)", handle);
        result = MU_FAILURE;
    }
    else
    {
        MQTT_CLIENT* mqtt_client = (MQTT_CLIENT*)handle;

        mqtt_client->packetState = UNKNOWN_TYPE;

        UINT    status;

        /* Initialize MQTT TLS.  */
        xware_mqtt_tls_init(&(mqtt_client -> xware_mqtt_client.nxd_mqtt_tls_session));

        /* Set the password.  */
        mqtt_client -> xware_mqtt_username = (char*)malloc(strlen(username) + 1);
        if (mqtt_client -> xware_mqtt_username == NULL)
        {
            LOG(AZ_LOG_ERROR, LOG_LINE, "Failed to allocate mqtt username.");
            result = MU_FAILURE;
            return result;
        }
        else
        {
            strcpy(mqtt_client -> xware_mqtt_username, username);
        }

        /* Set the password.  */
        mqtt_client -> xware_mqtt_password = (char*)malloc(strlen(password) + 1);
        if (mqtt_client -> xware_mqtt_password == NULL)
        {
            LOG(AZ_LOG_ERROR, LOG_LINE, "Failed to allocate mqtt username.");
            result = MU_FAILURE;
            return result;
        }
        else
        {
            strcpy(mqtt_client -> xware_mqtt_password, password);
        }

        /* Set the login user name and password.  */
        status = nxd_mqtt_client_login_set(&(mqtt_client -> xware_mqtt_client),
                                           mqtt_client -> xware_mqtt_username, strlen(mqtt_client -> xware_mqtt_username),
                                           mqtt_client -> xware_mqtt_password, strlen(mqtt_client -> xware_mqtt_password));

        /* Check status.  */
        if (status)
        {
            /*Codes_SRS_MQTT_CLIENT_07_007: [If any failure is encountered then mqtt_client_connect shall return a non-zero value.]*/
            LOG(AZ_LOG_ERROR, LOG_LINE, "Error: mqtt connect failed");
            result = MU_FAILURE;
            return result;
        }
                        
#ifdef XWARE_AZURE_IP_ADDRESS        
        mqtt_client -> xware_mqtt_host_address.nxd_ip_version = NX_IP_VERSION_V4;
        mqtt_client -> xware_mqtt_host_address.nxd_ip_address.v4 = XWARE_AZURE_IP_ADDRESS;
#else

        /* Get the Azure address.  */
        if (xware_host_address_get(&(mqtt_client -> xware_mqtt_host_address), host_name))
        {
            /*Codes_SRS_MQTT_CLIENT_07_007: [If any failure is encountered then mqtt_client_connect shall return a non-zero value.]*/
            LOG(AZ_LOG_ERROR, LOG_LINE, "Error: mqtt connect failed");
            result = MU_FAILURE;
            return result;
        }
#endif

        /* Connect to Azure.  */
        status = nxd_mqtt_client_secure_connect(&(mqtt_client -> xware_mqtt_client), &(mqtt_client -> xware_mqtt_host_address), XWARE_AZURE_PORT,
                                                xware_mqtt_tls_setup, 6 * NX_IP_PERIODIC_RATE, NX_TRUE,
                                                NX_WAIT_FOREVER);

        /* Check status.  */
        if (status)
        {
            /*Codes_SRS_MQTT_CLIENT_07_007: [If any failure is encountered then mqtt_client_connect shall return a non-zero value.]*/
            LOG(AZ_LOG_ERROR, LOG_LINE, "Error: mqtt connect failed");
            result = MU_FAILURE;
        }
        else
        {
            result = 0;
            mqtt_client->clientConnected = true;
        }

        /* Check the callback function.  */
        if (mqtt_client->fnOperationCallback != NULL)
        {

            CONNECT_ACK connack = { 0 };
            connack.isSessionPresent = true;
            if (status == 0)
                connack.returnCode = CONNECTION_ACCEPTED;
            else if (status == NXD_MQTT_ERROR_BAD_USERNAME_PASSWORD)
                connack.returnCode = CONN_REFUSED_BAD_USERNAME_PASSWORD;
            else if (status == NXD_MQTT_ERROR_NOT_AUTHORIZED)
                connack.returnCode = CONN_REFUSED_NOT_AUTHORIZED;
            else if (status == NXD_MQTT_ERROR_UNACCEPTABLE_PROTOCOL)
                connack.returnCode = CONN_REFUSED_UNACCEPTABLE_VERSION;
            else
                connack.returnCode = CONN_REFUSED_UNKNOWN;

            mqtt_client->fnOperationCallback(mqtt_client, MQTT_CLIENT_ON_CONNACK, (void*)&connack, mqtt_client->ctx);
        }
        else
        {
            LOG(AZ_LOG_ERROR, LOG_LINE, "fnOperationCallback NULL");
        }
    }
    return result;
}

int xware_mqtt_client_publish(MQTT_CLIENT_HANDLE handle, uint16_t packetId, const unsigned char* topic_name, size_t topic_name_len, const unsigned char* payload, size_t payload_len)
{
    int result;
    MQTT_CLIENT* mqtt_client = (MQTT_CLIENT*)handle;
    if (mqtt_client == NULL || topic_name == NULL)
    {
        /*Codes_SRS_MQTT_CLIENT_07_019: [If one of the parameters handle or msgHandle is NULL then mqtt_client_publish shall return a non-zero value.]*/
        LogError("Invalid parameter specified mqtt_client: %p, topic_name: %p, payload: %p", mqtt_client, topic_name, payload);
        result = MU_FAILURE;
    }
    else
    {

        /* Send publish message.  */
        mqtt_client ->xware_mqtt_client.nxd_mqtt_client_packet_identifier = packetId;
        if (nxd_mqtt_client_publish(&(mqtt_client ->xware_mqtt_client), (CHAR *)topic_name, topic_name_len,
                                    (CHAR*)payload, payload_len,
                                    0, DELIVER_AT_LEAST_ONCE, NX_NO_WAIT))
        {
            result = MU_FAILURE;
        }
        else
        {
            result = 0;
        }
    }
    return result;
}

int xware_mqtt_client_subscribe(MQTT_CLIENT_HANDLE handle, uint16_t packetId, SUBSCRIBE_PAYLOAD* subscribeList, size_t count)
{
    int result;
    int status;
    unsigned int i;
    MQTT_CLIENT* mqtt_client = (MQTT_CLIENT*)handle;
    if (mqtt_client == NULL || subscribeList == NULL || count == 0 || packetId == 0)
    {
        /*Codes_SRS_MQTT_CLIENT_07_013: [If any of the parameters handle, subscribeList is NULL or count is 0 then mqtt_client_subscribe shall return a non-zero value.]*/
        LogError("Invalid parameter specified mqtt_client: %p, subscribeList: %p, count: %d, packetId: %d", mqtt_client, subscribeList, count, packetId);
        result = MU_FAILURE;
    }
    else
    {

        result = 0;

        /* Loop to send subscribe message.  */
        for (i = 0; i < count; i++)
        {

            /* Send subscribe.  */
            mqtt_client ->xware_mqtt_client.nxd_mqtt_client_packet_identifier = packetId;
            status = nxd_mqtt_client_subscribe(&(mqtt_client ->xware_mqtt_client), (CHAR*)subscribeList[0].subscribeTopic,
                                               strlen(subscribeList[0].subscribeTopic), subscribeList[0].qosReturn);

            /* Check status.  */
            if (status)
            {

                /*Codes_SRS_MQTT_CLIENT_07_014: [If any failure is encountered then mqtt_client_subscribe shall return a non-zero value.]*/
                LOG(AZ_LOG_ERROR, LOG_LINE, "Error: mqtt_codec_subscribe failed");
                result = MU_FAILURE;
            }
        }
    }
    return result;
}

int xware_mqtt_client_unsubscribe(MQTT_CLIENT_HANDLE handle, uint16_t packetId, const char** unsubscribeList, size_t count)
{
    int result;
    int status;
    unsigned int i;
    MQTT_CLIENT* mqtt_client = (MQTT_CLIENT*)handle;
    if (mqtt_client == NULL || unsubscribeList == NULL || count == 0 || packetId == 0)
    {
        /*Codes_SRS_MQTT_CLIENT_07_016: [If any of the parameters handle, unsubscribeList is NULL or count is 0 then mqtt_client_unsubscribe shall return a non-zero value.]*/
        LogError("Invalid parameter specified mqtt_client: %p, unsubscribeList: %p, count: %d, packetId: %d", mqtt_client, unsubscribeList, count, packetId);
        result = MU_FAILURE;
    }
    else
    {

        result = 0;

        /* Loop to send unsubscribe message.  */
        for (i = 0; i < count; i++)
        {

            /* Send unsubscribe.  */
            mqtt_client ->xware_mqtt_client.nxd_mqtt_client_packet_identifier = packetId;
            status = nxd_mqtt_client_unsubscribe(&(mqtt_client ->xware_mqtt_client), (CHAR*)unsubscribeList[i], strlen(unsubscribeList[i]));

            /* Check status.  */
            if (status)
            {

                /*Codes_SRS_MQTT_CLIENT_07_017: [If any failure is encountered then mqtt_client_unsubscribe shall return a non-zero value.]*/
                LOG(AZ_LOG_ERROR, LOG_LINE, "Error: mqtt_codec_unsubscribe failed");
                result = MU_FAILURE;
            }
        }
    }
    return result;
}

int xware_mqtt_client_disconnect(MQTT_CLIENT_HANDLE handle, ON_MQTT_DISCONNECTED_CALLBACK callback, void* ctx)
{
    int result;
    MQTT_CLIENT* mqtt_client = (MQTT_CLIENT*)handle;
    if (mqtt_client == NULL)
    {
        /*Codes_SRS_MQTT_CLIENT_07_010: [If the parameters handle is NULL then mqtt_client_disconnect shall return a non-zero value.]*/
        result = MU_FAILURE;
    }
    else
    {
        if (mqtt_client->clientConnected)
        {

            mqtt_client->packetState = DISCONNECT_TYPE;

            /*Codes_SRS_MQTT_CLIENT_07_012: [On success mqtt_client_disconnect shall send the MQTT DISCONNECT packet to the endpoint.]*/
            if (nxd_mqtt_client_disconnect(&(mqtt_client -> xware_mqtt_client)) != 0)
            {
                /*Codes_SRS_MQTT_CLIENT_07_011: [If any failure is encountered then mqtt_client_disconnect shall return a non-zero value.]*/
                LOG(AZ_LOG_ERROR, LOG_LINE, "Error: mqtt_client_disconnect send failed");
                result = MU_FAILURE;
            }
            else
            {
                result = 0;
            }
            mqtt_client->clientConnected = false;
        }
        else
        {
            result = 0;
        }
    }
    return result;
}

void xware_mqtt_client_dowork(MQTT_CLIENT_HANDLE handle)
{

    UINT status;
    UINT topic_length;
    UINT message_length;

    MQTT_CLIENT* mqtt_client = (MQTT_CLIENT*)handle;
    /*Codes_SRS_MQTT_CLIENT_18_001: [If the client is disconnected, mqtt_client_dowork shall do nothing.]*/
    /*Codes_SRS_MQTT_CLIENT_07_023: [If the parameter handle is NULL then mqtt_client_dowork shall do nothing.]*/
    if (mqtt_client != NULL)
    {

        /* Get mqtt message.  */
        status = nxd_mqtt_client_message_get(&(mqtt_client ->xware_mqtt_client), xware_mqtt_client_topic,
                                             XWARE_MQTT_CLIENT_TOPIC_SIZE, &topic_length,
                                             xware_mqtt_client_message, XWARE_MQTT_CLIENT_MESSAGE_SIZE,
                                             &message_length);
        if(status == NXD_MQTT_SUCCESS)
        {
            xware_mqtt_client_topic[topic_length] = 0;
            xware_mqtt_client_message[message_length] = 0;

            /* Call the callback function.  */
            mqtt_client->fnMessageRecv((char*)xware_mqtt_client_topic, topic_length, (char*)xware_mqtt_client_message, message_length, mqtt_client->ctx);
        }
    }
}

void xware_mqtt_client_set_trace(MQTT_CLIENT_HANDLE handle, bool traceOn, bool rawBytesOn)
{
    MQTT_CLIENT* mqtt_client = (MQTT_CLIENT*)handle;
    if (mqtt_client != NULL)
    {
        mqtt_client->logTrace = traceOn;
        mqtt_client->rawBytesTrace = rawBytesOn;

        /* Unsupported feature yet.  */
    }
}
