/* libs/pixelflinger/codeflinger/ARMAssemblerInterface.cpp
**
** Copyright 2006, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License"); 
** you may not use this file except in compliance with the License. 
** You may obtain a copy of the License at 
**
**     http://www.apache.org/licenses/LICENSE-2.0 
**
** Unless required by applicable law or agreed to in writing, software 
** distributed under the License is distributed on an "AS IS" BASIS, 
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
** See the License for the specific language governing permissions and 
** limitations under the License.
*/


#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

#include <cutils/log.h>
#include "codeflinger/ARMAssemblerInterface.h"

namespace android {

// ----------------------------------------------------------------------------

ARMAssemblerInterface::~ARMAssemblerInterface()
{
}

// --------------------------------------------------------------------

// The following two functions are static and used for initializers
// in the original ARM code. The above versions (without __), are now
// virtual, and can be overridden in the MIPS code. But since these are
// needed at initialization time, they must be static. Not thrilled with
// this implementation, but it works...

uint32_t ARMAssemblerInterface::__immed12_pre(int32_t immed12, int W)
{
    LOG_ALWAYS_FATAL_IF(abs(immed12) >= 0x800,
                        "LDR(B)/STR(B)/PLD immediate too big (%08x)",
                        immed12);
    return (1<<24) | (((uint32_t(immed12)>>31)^1)<<23) |
            ((W&1)<<21) | (abs(immed12)&0x7FF);
}

uint32_t ARMAssemblerInterface::__immed8_pre(int32_t immed8, int W)
{
    uint32_t offset = abs(immed8);

    LOG_ALWAYS_FATAL_IF(abs(immed8) >= 0x100,
                        "LDRH/LDRSB/LDRSH/STRH immediate too big (%08x)",
                        immed8);

    return  (1<<24) | (1<<22) | (((uint32_t(immed8)>>31)^1)<<23) |
            ((W&1)<<21) | (((offset&0xF0)<<4)|(offset&0xF));
}


}; // namespace android

