/* Microsoft Reference Implementation for TPM 2.0
 *
 *  The copyright in this software is being made available under the BSD License,
 *  included below. This software may be subject to other third party and
 *  contributor rights, including patent rights, and no such rights are granted
 *  under this license.
 *
 *  Copyright (c) Microsoft Corporation
 *
 *  All rights reserved.
 *
 *  BSD License
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this list
 *  of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ""AS IS""
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#if !defined(_MSC_VER) && defined(USE_DEVICE_PERSISTENT_IDENTITY)
#define _CRT_RAND_S
#include <stdlib.h>
#include <memory.h>
#include <time.h>
#include "Platform.h"

#include <unistd.h>
#include <net/if.h> 
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdbool.h>
#include <libudev.h>
#include <sys/stat.h>

// This value is used to store persistent entropy for the device by deriving from hardware parameters.
// Entropy is the size of a the state. The state is the size of the key
// plus the IV. The IV is a block. If Key = 256 and Block = 128 then State = 384
// Currently simulator supports key size 256 or 128
#define ENTROPY_MAX_SIZE_BYTES 48

const unsigned int MAC_ADDRESS_MAXIMUM_SIZE = 6;
static bool isEntropySet = false;
static unsigned char devicePersistentEntropy[ENTROPY_MAX_SIZE_BYTES];

// Read mac address of the device and copy over to the given buffer.
// Returns 0 for success and -1 for error.

static int getMacAddress(unsigned char* macAddress, const unsigned int macAddressSize)
{

    if ((macAddress == NULL) || (macAddressSize == 0))
    {
        fprintf(stderr, "Invalid input arguments.");
        return -1;
    }

    struct ifreq interfaceRequest = {0};
    struct ifconf interfaceConfiguration = {0};
    char interfaceConfigurationBuffer[1024] = {0};

    int inetSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (inetSocket == -1)
    {
        return -1;
    }

    interfaceConfiguration.ifc_len = sizeof(interfaceConfigurationBuffer);
    interfaceConfiguration.ifc_buf = interfaceConfigurationBuffer;
    if((ioctl(inetSocket, SIOCGIFCONF, &interfaceConfiguration)) == -1)
    {
        close(inetSocket);
        return -1;
    }

    struct ifreq* intefaceRequestStart = interfaceConfiguration.ifc_req;
    const struct ifreq* const interfaceRequestEnd = intefaceRequestStart + (interfaceConfiguration.ifc_len / sizeof(struct ifreq));

    int32_t result = -1;

    for (; intefaceRequestStart != interfaceRequestEnd; ++intefaceRequestStart)
    {
        strcpy(interfaceRequest.ifr_name, intefaceRequestStart->ifr_name);
        if (ioctl(inetSocket, SIOCGIFFLAGS, &interfaceRequest) == 0)
        {
            // don't count loopback
            if ((interfaceRequest.ifr_flags & IFF_LOOPBACK) == 0)
            {
                if (ioctl(inetSocket, SIOCGIFHWADDR, &interfaceRequest) == 0)
                {
                    result = 0;
                    break;
                }
            }
        }
        else
        {
            break;
        }
    }

    if (result == 0)
    {
        unsigned int size = macAddressSize <= MAC_ADDRESS_MAXIMUM_SIZE ? macAddressSize : MAC_ADDRESS_MAXIMUM_SIZE;
        memset(macAddress, 0, size);
        memcpy(macAddress, interfaceRequest.ifr_hwaddr.sa_data, size);
    }

    close(inetSocket);
    return result;
}

// Read primary harddisk/emmc disk serial id from device and copy over to the given buffer.
// Returns 0 for success and -1 for error.

static int getDiskSerialNumber(unsigned char* diskSerialNumber, const unsigned int diskSerialNumberSize)
{
    struct udev *ud = NULL;
    struct stat statbuf;
    struct udev_device *device = NULL;
    struct udev_list_entry *entry = NULL;
    int result = -1;

    ud = udev_new();
    if (NULL == ud)
    {
        fprintf(stderr, "\nFailed to create udev.\n");
        return result;
    }
    else
    {

        const unsigned int diskDeviceNamesSize = 2;
        const char *diskDeviceNames[] = {
            "/dev/sda", // primary hard disk.
            "/dev/mmcblk0" // primary eMMC disk.
        };

        unsigned int i = 0;
        while (i < diskDeviceNamesSize)
        {
            if (0 == stat(diskDeviceNames[i], &statbuf))
            {
                break;
            }
            else
            {
                fprintf(stderr, "\nFailed to stat %s.\n", diskDeviceNames[i]);
            }
            i++;
        }

        if (i == diskDeviceNamesSize)
        {
            goto Cleanup;
        }

        const char blockDeviceType = 'b';
        device = udev_device_new_from_devnum(ud, blockDeviceType, statbuf.st_rdev);
        if (NULL == device)
        {
            fprintf(stderr, "\nFailed to open %s.\n", diskDeviceNames[i]);
            goto Cleanup;
        }
        else
        {
            entry = udev_device_get_properties_list_entry(device);
            while (NULL != entry)
            {
                if (0 == strcmp(udev_list_entry_get_name(entry),
                    "ID_SERIAL")) 
                {
                    break;
                }

                entry = udev_list_entry_get_next(entry);
            }

            if(entry == NULL)
            {
                goto Cleanup;
            }

            const char* serialNumber = udev_list_entry_get_value(entry);
            size_t serialNumberLength = strlen(serialNumber);
            size_t dataLengthToCopy = serialNumberLength < diskSerialNumberSize ? serialNumberLength : diskSerialNumberSize;
            memcpy(diskSerialNumber, serialNumber, dataLengthToCopy);

            result = 0;
        }

Cleanup:
        if(device == NULL)
        {
            udev_device_unref(device);
        }

        (void)udev_unref(ud);
        return result;
    }
}

//*** GetDeviceEntropy()
// This function is used to get device entropy from device hardware parameters.
//  Return Type: int32_t
//  < 0        failure to get hardware entropy.
// >= 0        the returned amount of entropy (bytes)
// Note that, it is only used to get persistent identity, it is unsecure to rely on this entropy.
// pre-requisites - assumes that MAC address is present for the device.
int32_t
GetDeviceEntropy(
    unsigned char       *entropy,           // output buffer
    uint32_t             amount             // amount requested
)
{

    if(!isEntropySet)
    {
        memset(devicePersistentEntropy, 0, ENTROPY_MAX_SIZE_BYTES);

        if(getMacAddress(devicePersistentEntropy, MAC_ADDRESS_MAXIMUM_SIZE) == -1)
        {
            fprintf(stderr, "\nerror occurred in retrieving mac address.\n");
        }
        else
        {
            isEntropySet = true;
        }

        if(getDiskSerialNumber(&devicePersistentEntropy[MAC_ADDRESS_MAXIMUM_SIZE], ENTROPY_MAX_SIZE_BYTES - MAC_ADDRESS_MAXIMUM_SIZE) == -1)
        {
            fprintf(stderr, "\nerror occurred in retrieving disk serial.\n");
        }
        else
        {
            isEntropySet = true;
        }

        if(!isEntropySet)
        {
            return -1;
        }
    }

    if(amount == 0)
    {
        return 0;
    }
    else
    {
        if(amount > ENTROPY_MAX_SIZE_BYTES)
        {
            fprintf(stderr, "\namount>ENTROPY_MAX_SIZE_BYTES called.\n");
            return -1;
        }
        else
        {
            memcpy(entropy, devicePersistentEntropy, amount);
            return amount;
        }
    }
}
#endif