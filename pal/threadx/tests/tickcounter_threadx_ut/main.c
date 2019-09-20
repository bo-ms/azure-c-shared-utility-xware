// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "testrunnerswitcher.h"
#include "tx_api.h"

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

int main(void)
{

    /* Enter the ThreadX kernel.  */
    tx_kernel_enter();
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

    size_t failedTestCount = 0;
    RUN_TEST_SUITE(tickcounter_unittests, failedTestCount);
}

