// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// Copyright (c) Express Logic.  All rights reserved.
// Please contact support@expresslogic.com for any questions or use the support portal at www.rtos.com


#ifndef TLSIO_XWARE_H
#define TLSIO_XWARE_H

#include "nx_api.h"
#include "nx_secure_tls_api.h"

#include "azure_c_shared_utility/xio.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/optionhandler.h"

#ifdef __cplusplus
extern "C" {
#include <cstddef>
#else
#include <stddef.h>
#endif /* __cplusplus */

// DEPRECATED: the functions below do not neet to be exposed.
extern CONCRETE_IO_HANDLE tlsio_xware_tls_create(void* io_create_parameters);
extern void tlsio_xware_tls_destroy(CONCRETE_IO_HANDLE tls_io);
extern int tlsio_xware_tls_open(CONCRETE_IO_HANDLE tls_io, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context, ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context, ON_IO_ERROR on_io_error, void* on_io_error_context);
extern int tlsio_xware_tls_close(CONCRETE_IO_HANDLE tls_io, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context);
extern int tlsio_xware_tls_send(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context);
extern void tlsio_xware_tls_dowork(CONCRETE_IO_HANDLE tls_io);
extern int tlsio_xware_tls_setoption(CONCRETE_IO_HANDLE tls_io, const char* optionName, const void* value);
extern OPTIONHANDLER_HANDLE tlsio_xware_tls_retrieveoptions(CONCRETE_IO_HANDLE handle);
// DEPRECATED: the functions above do not neet to be exposed.

extern const IO_INTERFACE_DESCRIPTION* tlsio_xware_tls_get_interface_description(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* TLSIO_XWARE_H */
