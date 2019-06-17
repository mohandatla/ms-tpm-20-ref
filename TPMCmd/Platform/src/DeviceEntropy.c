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

// This value is used to store persistent entropy for the device by deriving from hardware parameters.
// Entropy is the size of a the state. The state is the size of the key
// plus the IV. The IV is a block. If Key = 256 and Block = 128 then State = 384
// Currently simulator supports key size 256 or 128
#define ENTROPY_MAX_SIZE_BYTES   48

const unsigned int MAC_ADDRESS_MAXIMUM_SIZE = 6;
static bool isEntropySet = false;
static BYTE devicePersistentEntropy[ENTROPY_MAX_SIZE_BYTES];

static int32_t GetMacAddress(unsigned char* macAddress, const unsigned int macAddressSize)
{
    struct ifreq interfaceRequest;
    struct ifconf interfaceConfiguration;
    char interfaceConfigurationBuffer[1024];

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
            if (!(interfaceRequest.ifr_flags & IFF_LOOPBACK))
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

    if ((result == 0) && (macAddress != NULL))
    {
        unsigned int size = macAddressSize <= MAC_ADDRESS_MAXIMUM_SIZE ? macAddressSize : MAC_ADDRESS_MAXIMUM_SIZE;
        memset(macAddress, 0, size);
        memcpy(macAddress, interfaceRequest.ifr_hwaddr.sa_data, size);
    }

    close(inetSocket);
    return result;
}

static int32_t GetDiskSerialNumber(unsigned char* diskSerialNumber, const unsigned int diskSerialNumberSize)
{
    // todo
    return 0;
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
    int32_t result = 0;

    if(!isEntropySet)
    {
        memset(devicePersistentEntropy, 0, ENTROPY_MAX_SIZE_BYTES);

        if(GetMacAddress(devicePersistentEntropy, MAC_ADDRESS_MAXIMUM_SIZE) == -1)
        {
            printf("error occurred in retrieving mac address.\n");
        }
        else
        {
            isEntropySet = true;
        }

        if(GetDiskSerialNumber(&devicePersistentEntropy[MAC_ADDRESS_MAXIMUM_SIZE], ENTROPY_MAX_SIZE_BYTES - MAC_ADDRESS_MAXIMUM_SIZE) == -1)
        {
            printf("error occurred in retrieving disk serial.\n");
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
        printf("amount=0 called.\n");
        return 0;
    }
    else
    {
        if(amount > ENTROPY_MAX_SIZE_BYTES)
        {
            printf("amount>ENTROPY_MAX_SIZE_BYTES called.\n");
            result = -1;
        }
        else
        {
            memcpy(entropy, devicePersistentEntropy, amount);
            result = amount;
        }
    }
    return result;
}
#endif