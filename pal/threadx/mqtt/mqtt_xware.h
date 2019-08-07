// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// Copyright (c) Express Logic.  All rights reserved.
// Please contact support@expresslogic.com for any questions or use the support portal at www.rtos.com

#ifndef MQTT_XWARE_H
#define MQTT_XWARE_H

#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_macro_utils/macro_utils.h"

#include "azure_c_shared_utility/xio.h"
#include "azure_macro_utils/macro_utils.h"
#include "umock_c/umock_c_prod.h"

#include "iothub_client_ll.h"

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif // __cplusplus

#define CONTROL_PACKET_TYPE_VALUES \
    CONNECT_TYPE = 0x10, \
    CONNACK_TYPE = 0x20, \
    PUBLISH_TYPE = 0x30, \
    PUBACK_TYPE = 0x40, \
    PUBREC_TYPE = 0x50, \
    PUBREL_TYPE = 0x60, \
    PUBCOMP_TYPE = 0x70, \
    SUBSCRIBE_TYPE = 0x80, \
    SUBACK_TYPE = 0x90, \
    UNSUBSCRIBE_TYPE = 0xA0, \
    UNSUBACK_TYPE = 0xB0, \
    PINGREQ_TYPE = 0xC0, \
    PINGRESP_TYPE = 0xD0, \
    DISCONNECT_TYPE = 0xE0, \
    PACKET_TYPE_ERROR, \
    UNKNOWN_TYPE

MU_DEFINE_ENUM(CONTROL_PACKET_TYPE, CONTROL_PACKET_TYPE_VALUES)

#define QOS_VALUE_VALUES \
    DELIVER_AT_MOST_ONCE = 0x00, \
    DELIVER_AT_LEAST_ONCE = 0x01, \
    DELIVER_EXACTLY_ONCE = 0x02, \
    DELIVER_FAILURE = 0x80

MU_DEFINE_ENUM(QOS_VALUE, QOS_VALUE_VALUES)

typedef struct APP_PAYLOAD_TAG
{
    uint8_t* message;
    size_t length;
} APP_PAYLOAD;

typedef struct MQTT_CLIENT_OPTIONS_TAG
{
    char* clientId;
    char* willTopic;
    char* willMessage;
    char* username;
    char* password;
    uint16_t keepAliveInterval;
    bool messageRetain;
    bool useCleanSession;
    QOS_VALUE qualityOfServiceValue;
    bool log_trace;
} MQTT_CLIENT_OPTIONS;

typedef enum CONNECT_RETURN_CODE_TAG
{
    CONNECTION_ACCEPTED = 0x00,
    CONN_REFUSED_UNACCEPTABLE_VERSION = 0x01,
    CONN_REFUSED_ID_REJECTED = 0x02,
    CONN_REFUSED_SERVER_UNAVAIL = 0x03,
    CONN_REFUSED_BAD_USERNAME_PASSWORD = 0x04,
    CONN_REFUSED_NOT_AUTHORIZED = 0x05,
    CONN_REFUSED_UNKNOWN
} CONNECT_RETURN_CODE;

typedef struct CONNECT_ACK_TAG
{
    bool isSessionPresent;
    CONNECT_RETURN_CODE returnCode;
} CONNECT_ACK;

typedef struct SUBSCRIBE_PAYLOAD_TAG
{
    const char* subscribeTopic;
    QOS_VALUE qosReturn;
} SUBSCRIBE_PAYLOAD;

typedef struct SUBSCRIBE_ACK_TAG
{
    uint16_t packetId;
    QOS_VALUE* qosReturn;
    size_t qosCount;
} SUBSCRIBE_ACK;

typedef struct UNSUBSCRIBE_ACK_TAG
{
    uint16_t packetId;
} UNSUBSCRIBE_ACK;

typedef struct PUBLISH_ACK_TAG
{
    uint16_t packetId;
} PUBLISH_ACK;



typedef struct MQTT_CLIENT_TAG* MQTT_CLIENT_HANDLE;

#define MQTT_CLIENT_EVENT_VALUES     \
    MQTT_CLIENT_ON_CONNACK,          \
    MQTT_CLIENT_ON_PUBLISH_ACK,      \
    MQTT_CLIENT_ON_PUBLISH_RECV,     \
    MQTT_CLIENT_ON_PUBLISH_REL,      \
    MQTT_CLIENT_ON_PUBLISH_COMP,     \
    MQTT_CLIENT_ON_SUBSCRIBE_ACK,    \
    MQTT_CLIENT_ON_UNSUBSCRIBE_ACK,  \
    MQTT_CLIENT_ON_PING_RESPONSE,    \
    MQTT_CLIENT_ON_DISCONNECT

MU_DEFINE_ENUM(MQTT_CLIENT_EVENT_RESULT, MQTT_CLIENT_EVENT_VALUES);

#define MQTT_CLIENT_EVENT_ERROR_VALUES     \
    MQTT_CLIENT_CONNECTION_ERROR,          \
    MQTT_CLIENT_PARSE_ERROR,               \
    MQTT_CLIENT_MEMORY_ERROR,              \
    MQTT_CLIENT_COMMUNICATION_ERROR,       \
    MQTT_CLIENT_NO_PING_RESPONSE,          \
    MQTT_CLIENT_UNKNOWN_ERROR

MU_DEFINE_ENUM(MQTT_CLIENT_EVENT_ERROR, MQTT_CLIENT_EVENT_ERROR_VALUES);

typedef void(*ON_MQTT_OPERATION_CALLBACK)(MQTT_CLIENT_HANDLE handle, MQTT_CLIENT_EVENT_RESULT actionResult, const void* msgInfo, void* callbackCtx);
typedef void(*ON_MQTT_ERROR_CALLBACK)(MQTT_CLIENT_HANDLE handle, MQTT_CLIENT_EVENT_ERROR error, void* callbackCtx);
typedef void(*ON_MQTT_MESSAGE_RECV_CALLBACK)(char* topic, size_t topic_length, char* message, size_t message_length, void* callbackCtx);
typedef void(*ON_MQTT_DISCONNECTED_CALLBACK)(void* callbackCtx);

MOCKABLE_FUNCTION(, MQTT_CLIENT_HANDLE, xware_mqtt_client_init, const IOTHUB_CLIENT_CONFIG*, upperConfig, ON_MQTT_MESSAGE_RECV_CALLBACK, msgRecv, ON_MQTT_OPERATION_CALLBACK, opCallback, void*, opCallbackCtx, ON_MQTT_ERROR_CALLBACK, onErrorCallBack, void*, errorCBCtx);
MOCKABLE_FUNCTION(, void, xware_mqtt_client_deinit, MQTT_CLIENT_HANDLE, handle);

MOCKABLE_FUNCTION(, int, xware_mqtt_client_connect, MQTT_CLIENT_HANDLE, handle, const char*, hostname, const char*, username, char*, password);
MOCKABLE_FUNCTION(, int, xware_mqtt_client_disconnect, MQTT_CLIENT_HANDLE, handle, ON_MQTT_DISCONNECTED_CALLBACK, callback, void*, ctx);

MOCKABLE_FUNCTION(, int, xware_mqtt_client_subscribe, MQTT_CLIENT_HANDLE, handle, uint16_t, packetId, SUBSCRIBE_PAYLOAD*, subscribeList, size_t, count);
MOCKABLE_FUNCTION(, int, xware_mqtt_client_unsubscribe, MQTT_CLIENT_HANDLE, handle, uint16_t, packetId, const char**, unsubscribeList, size_t, count);

MOCKABLE_FUNCTION(, int, xware_mqtt_client_publish, MQTT_CLIENT_HANDLE, handle, uint16_t, packetId, const unsigned char*, topic_name, size_t, topic_name_len, const unsigned char*, payload, size_t, payload_len);

MOCKABLE_FUNCTION(, void, xware_mqtt_client_dowork, MQTT_CLIENT_HANDLE, handle);

MOCKABLE_FUNCTION(, void, xware_mqtt_client_set_trace, MQTT_CLIENT_HANDLE, handle, bool, traceOn, bool, rawBytesOn);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // MQTT_XWARE_H
