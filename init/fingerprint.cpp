 /*
 * Copyright (C) 2021 The Android Open Source Project
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

std::string prop_build_base_os = "ro.build.version.base_os";

std::string get_fingerprint_property_string() {
    std::string build_fingerprint = android::base::GetProperty("ro.build.fingerprint", "");
    std::string brand_name = android::base::GetProperty("ro.product.brand", "");
    std::string product_name = android::base::GetProperty("ro.product.name", "");
    std::string device_name = android::base::GetProperty("ro.product.device", "");

    // Fingerprint format:
    // $(BRAND)/$(PRODUCT)/$(DEVICE):$(VERSION.RELEASE)/$(ID)/$(VERSION.INCREMENTAL):$(TYPE)/$(TAGS)
    // brand, product and device may change on different carrier, so replace them.
    std::vector<std::string> fingerprint = android::base::Split(build_fingerprint, ":");
    std::vector<std::string> name = android::base::Split(fingerprint[0], "/");
    const int count = name.size();

    // To avoid invalid array index, check name size.
    if (count > 0) name[0] = brand_name;
    if (count > 1) name[1] = product_name;
    if (count > 2) name[2] = device_name;

    fingerprint[0] = android::base::Join(name, "/");
    return android::base::Join(fingerprint, ":");
}

std::string get_base_os_property() {
    std::string  build_base_os = android::base::GetProperty(prop_build_base_os, "");
    if (build_base_os.empty()) return "";
    std::string  brand_value = android::base::GetProperty("ro.product.brand", "");
    std::string  product_value = android::base::GetProperty("ro.product.name", "");

    std::vector<std::string> base_os = android::base::Split(build_base_os, "/");
    base_os[0] = brand_value;
    base_os[1] = product_value;
    return android::base::Join(base_os, "/");
}

void set_fingerprint_property() {
    std::string fingerprint = get_fingerprint_property_string();

    //set_base_os_fingerprint
    std::string base_os = get_base_os_property();
    android::init::InitPropertySet(prop_build_base_os, base_os);

    std::string properties[] =
    {
        "ro.build.fingerprint", "ro.bootimage.build.fingerprint", "ro.system.build.fingerprint",
        "ro.odm.build.fingerprint", "ro.system_ext.build.fingerprint", "ro.vendor.build.fingerprint",
        "ro.product.build.fingerprint",
    };
    const int count = sizeof(properties) / sizeof(std::string);

    for (int i = 0; i < count; i++)
    {
        android::init::InitPropertySet(properties[i], fingerprint);
    }
}
