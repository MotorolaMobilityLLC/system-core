/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "property_info.h"
#include "property_service.h"

#include <android-base/properties.h>
#include <android-base/strings.h>
#include <string>
#include <android-base/logging.h>
#include <android-base/file.h>
#include "cutils/log.h"
#include <fstream>
#include <sstream>
#include <iostream>



namespace android {
namespace init {

std::string prop_product_device = "ro.product.device";
std::string prop_product_vendor_device = "ro.product.vendor.device";
std::string prop_product_odm_device = "ro.product.odm.device";
std::string prop_product_system_device = "ro.product.system.device";
std::string prop_product_product_device = "ro.product.product.device";

void set_system_properties(){
    std::string prop_cpu_value = android::base::GetProperty("ro.product.cpu.abi", "");
    if (prop_cpu_value == "arm64-v8a"){
        set_product_device("cyprus64");
    }
    else{
        set_product_device("cyprus");
    }
}


void set_product_device(std::string product_device) {
    InitPropertySet(prop_product_device, product_device);
    InitPropertySet(prop_product_vendor_device, product_device);
    InitPropertySet(prop_product_system_device, product_device);
    InitPropertySet(prop_product_odm_device, product_device);
    InitPropertySet(prop_product_product_device, product_device);
}


bool changeSystemProperty(std::string key) {
    if ( key == prop_product_device || key == prop_product_system_device
      || key == prop_product_odm_device || key == prop_product_product_device
      || key == prop_product_vendor_device ) {
        return true;
    }
    return false;
}



}  // namespace init
} // namespace android
