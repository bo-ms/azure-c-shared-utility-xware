// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "testrunnerswitcher.h"
#include "nx_api.h"
#include "azure_c_shared_utility/platform.h"

/* Define the helper thread for running Azure SDK on ThreadX (X-Ware IoT Platform).  */
#ifndef XWARE_AZURE_SDK_HELPER_THREAD_STACK_SIZE
#define XWARE_AZURE_SDK_HELPER_THREAD_STACK_SIZE        (2048)
#endif /* XWARE_AZURE_SDK_HELPER_THREAD_STACK_SIZE  */

#ifndef XWARE_AZURE_SDK_HELPER_THREAD_PRIORITY
#define XWARE_AZURE_SDK_HELPER_THREAD_PRIORITY          (4)
#endif /* XWARE_AZURE_SDK_HELPER_THREAD_PRIORITY  */

/* Define the memory area for helper thread.  */
UCHAR xware_azure_sdk_helper_thread_stack[XWARE_AZURE_SDK_HELPER_THREAD_STACK_SIZE];

/* Define the prototypes for helper thread.  */
TX_THREAD xware_azure_sdk_helper_thread;
void xware_azure_sdk_helper_thread_entry(ULONG parameter);
extern void xware_azure_sdk_initialize(void);

void (*platform_driver_get())(NX_IP_DRIVER *);
extern VOID _nx_pcap_network_driver(NX_IP_DRIVER*); 

int main(void)
{

    /* Enter the ThreadX kernel.  */
    tx_kernel_enter();
}


/* Get the network driver.  */
VOID (*platform_driver_get())(NX_IP_DRIVER *)
{
    return(_nx_pcap_network_driver);
}

/* Define what the initial system looks like.  */
void tx_application_define(void *first_unused_memory)
{

UINT  status;

    /* Create XWARE Azure SDK helper thread. */
    status = tx_thread_create(&xware_azure_sdk_helper_thread, "XWARE Azure SDK Help Thread",
                     xware_azure_sdk_helper_thread_entry, 0,
                     xware_azure_sdk_helper_thread_stack, XWARE_AZURE_SDK_HELPER_THREAD_STACK_SIZE,
                     XWARE_AZURE_SDK_HELPER_THREAD_PRIORITY, XWARE_AZURE_SDK_HELPER_THREAD_PRIORITY, 
                     TX_NO_TIME_SLICE, TX_AUTO_START);    
    
    /* Check status.  */
    if (status)
        printf("XWARE Azure SDK Helper Thread Create Fail.\r\n");
}

/* Define XWARE Azure SDK helper thread entry.  */
void xware_azure_sdk_helper_thread_entry(ULONG parameter)
{

    /* Initialize XWARE.  */
    platform_init();

    size_t failedTestCount = 0;
    RUN_TEST_SUITE(socketio_threadx_unittests, failedTestCount);
}
