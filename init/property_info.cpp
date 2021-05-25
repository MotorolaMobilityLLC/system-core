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

std::string prop_product = "ro.product.name";
std::string prop_product_value;
std::string prop_product_vendor_name = "ro.product.vendor.name";
std::string prop_product_odm_name = "ro.product.odm.name";
std::string prop_product_system_name = "ro.product.system.name";
std::string prop_product_system_ext_name = "ro.product.system_ext.name";
std::string prop_product_product_name = "ro.product.product.name";

void set_system_properties(){
    prop_product_value = android::base::GetProperty(prop_product, "");
    if (prop_product_value == "cyprus64"){
        set_product_name(prop_product_value);
    } else if(prop_product_value == "cyprus"){
        set_product_name(prop_product_value);
    }
}

void set_product_name(std::string product_name) {
    InitPropertySet(prop_product, product_name);
    InitPropertySet(prop_product_vendor_name, product_name);
    InitPropertySet(prop_product_system_name, product_name);
    InitPropertySet(prop_product_system_ext_name, product_name);
    InitPropertySet(prop_product_product_name, product_name);
    InitPropertySet(prop_product_odm_name, product_name);
}

bool changeSystemProperty(std::string key) {
    if ( key == prop_product || key == prop_product_vendor_name
      || key == prop_product_system_name || key == prop_product_system_ext_name
      || key == prop_product_product_name || key == prop_product_odm_name) {
        return true;
    }
    return false;
}



}  // namespace init
} // namespace android
