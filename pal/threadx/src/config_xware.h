// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// Copyright (c) Express Logic.  All rights reserved.
// Please contact support@expresslogic.com for any questions or use the support portal at www.rtos.com


#ifndef CONFIG_XWARE_H
#define CONFIG_XWARE_H

#ifdef __cplusplus
extern "C" {
#include <cstddef>
#else
#include <stddef.h>
#endif /* __cplusplus */

/* The user can override this via -D command line option or via project settings.  */

/* Define the address of Azure IoT Hub. Use DNS module to resolve the host name of Azure IoT Hub by default.
   If XWARE_AZURE_IP_ADDRESS is set, XWARE will directly use this address without the need for DNS resolver.
   The address of US Azure IoT Hub (xware-azure-demo.azure-devices.net) is 40.83.177.42.  */
/*
#define XWARE_AZURE_IP_ADDRESS              IP_ADDRESS(40, 78, 22, 17)
*/

/* Define the port of Azure IoT Hub.  */
#ifndef XWARE_AZURE_PORT
#define XWARE_AZURE_PORT                    8883
#endif /* XWARE_AZURE_PORT  */


/* mqtt_xware.c  */
/* Define stack size for XWARE MQTT client thread.  */
#ifndef XWARE_MQTT_CLIENT_STACK_SIZE
#define XWARE_MQTT_CLIENT_STACK_SIZE        2048
#endif /* XWARE_MQTT_CLIENT_STACK_SIZE  */

/* Define stack priority for XWARE MQTT client thread.  */
#ifndef XWARE_MQTT_CLIENT_PRIORITY
#define XWARE_MQTT_CLIENT_PRIORITY          2
#endif /* XWARE_MQTT_CLIENT_PRIORITY  */

/* Define the topic size to store the topic from IoT Hub(subscribe).  */
#ifndef XWARE_MQTT_CLIENT_TOPIC_SIZE
#define XWARE_MQTT_CLIENT_TOPIC_SIZE        200
#endif /* XWARE_MQTT_CLIENT_TOPIC_SIZE  */

/* Define the message size to stroe the message(payload) from IoT Hub (subscribe).  */
#ifndef XWARE_MQTT_CLIENT_MESSAGE_SIZE
#define XWARE_MQTT_CLIENT_MESSAGE_SIZE      200
#endif /* XWARE_MQTT_CLIENT_MESSAGE_SIZE  */

/* Define memory size to store the sending message block for XWARE MQTT client QOS1 (publish).  */
#ifndef XWARE_MQTT_CLIENT_MEMORY
#define XWARE_MQTT_CLIENT_MEMORY            1500
#endif /* XWARE_MQTT_CLIENT_MEMORY  */


/* tlsio_xware.c  */
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


/* threadapi_xware.c */
/* Define the amount of memory for the memory pool ThreadX will utilize for the Azure porting layer. 
   The user can override this via -D command line option or via project settings. */
#ifndef XWARE_AZURE_SDK_MEMORY_POOL_SIZE
#define XWARE_AZURE_SDK_MEMORY_POOL_SIZE    8196
#endif

/* Define the default thread attributes, priority, stack size, etc.  The user can override this 
   via -D command line option or via project settings.  */
#ifndef XWARE_AZURE_SDK_THREAD_PRIORITY
#define XWARE_AZURE_SDK_THREAD_PRIORITY     16
#endif

#ifndef XWARE_AZURE_SDK_THREAD_STACK_SIZE
#define XWARE_AZURE_SDK_THREAD_STACK_SIZE   2048
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CONFIG_XWARE_H */
