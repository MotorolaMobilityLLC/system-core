/* libs/pixelflinger/scanline.h
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


#ifndef ANDROID_SCANLINE_H
#define ANDROID_SCANLINE_H

#include <private/pixelflinger/ggl_context.h>

namespace android {

void ggl_init_scanline(context_t* c);
void ggl_uninit_scanline(context_t* c);
void ggl_pick_scanline(context_t* c);

}; // namespace android

#endif
