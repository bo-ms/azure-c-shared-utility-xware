
# ThreadX

[ThreadX RTOS](https://rtos.com/) is advanced Industrial Grade Real-Time Operating System (RTOS) designed specifically for deeply embedded, real-time, and IoT applications.

## Dependencies

Makesure have threadx code before running azure-c-shared-utility on threadx.

src folder includes the threadx porting files.

tests folder includes the unit tests on threadx platform.

## Setup On Windows

1. Clone **azure-c-shared-utility** test project on threadx using the recursive option:

```
git clone --recursive https://ExpressLogic@dev.azure.com/ExpressLogic/X-Ware/_git/project-X-Ware azure-c-shared-utility-test -b azure-c-shared-utility-test
```

2. Switch to azure-c-shared-utility-test/xware-vs folder

3. Run update_lib.bat to generate the source code files and test files

4. Click xware-vs.sln to open and build the projects

5. Run the tests

## Porting to new devices

Instructions for porting the Azure IoT C SDK to new devices are located
[here](https://github.com/Azure/azure-c-shared-utility/blob/master/devdoc/porting_guide.md).
