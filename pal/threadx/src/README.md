
# ThreadX

[ThreadX RTOS](https://rtos.com/) is advanced Industrial Grade Real-Time Operating System (RTOS) designed specifically for deeply embedded, real-time, and IoT applications.

## Overview

ThreadX provide following components for SDK:

- A `platform` implementation to perform global init and de-init on ThreadX platform, platform_xware.c.

- A `threadapi` implementation to provide a threading function, threadapi_xware.c.

- A `sleep` implementation to provide a device-independent sleep function, threadapi_xware.

- A `lock` implementation to provide a synchronization needed function, lock_xware.c.

- A `tickcounter` implementation: this provides the SDK an adapter for getting a tick counter expressed in ms, 
tickcounter_xware.c.

- A `socketio` implementation to provide an IO interface, abstracting from upper layers the functionality of 
simply sending or receiving byetes, socketio_xware.c.

- A `tlsio` implementation to allow the SDK to communicate over TLS. The IoT Hub does not support insecure
communication, tlsio_xware.c.

## Porting to new devices

Instructions for porting the Azure IoT C SDK to ThreadX devices are located
[here](https://github.com/Azure/azure-c-shared-utility/blob/master/devdoc/porting_guide.md).
