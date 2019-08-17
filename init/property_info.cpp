
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

std::string prop_build_customerid = "ro.mot.build.customerid";
std::string prop_build_fullversion = "ro.build.version.full";
std::string prop_product_locale = "ro.product.locale";
std::string prop_build_id = "ro.build.id";
std::string prop_carrier_ontim = "ro.carrier.ontim";
std::string prop_carrier = "ro.carrier";
std::string prop_amclient = "ro.com.google.clientidbase.am";
std::string prop_msclient = "ro.com.google.clientidbase.ms";
std::string prop_product = "ro.product.name";
std::string prop_build_fingerprint = "ro.bootimage.build.fingerprint";
std::string prop_fingerprint = "ro.build.fingerprint";
std::string prop_vendor_fingerprint = "ro.vendor.build.fingerprint";
std::string prop_client_value = "android-motorola";
std::string prop_clientrev_value = "android-motorola-rev2";
std::string prop_clientcountry_value = "android-americamovil-{country}";
std::string prop_clientrevc_value = "android-americamovil-{country}-revc";
std::string prop_clientmx_value = "android-attmexico-mx-revc";
std::string prop_clientuk_value = "android-ee-uk-revc";
std::string prop_clientbr_value = "android-tim-br-revc";
std::string prop_clienttmobile_value = "android-tmobile-{country}";
std::string prop_clientdt_value = "android-dt-{country}-revc";
std::string prop_product_value = "bali";
std::string prop_carrier_value = "retail";
std::string prop_version_value;
std::string product_version_file = "/product/version.txt";

void set_system_properties(){
    std::ifstream stream(product_version_file);
    std::stringstream fileStream;
    fileStream << stream.rdbuf();
    std::string fileContent = fileStream.str().substr(0,3);
    std::string  carrier_ontim = android::base::GetProperty(prop_carrier_ontim, "");
    size_t position = carrier_ontim.find("_");
    std::string  carrier_value = carrier_ontim.substr(0, position);
    property_set(prop_carrier,carrier_value);
    property_set("ro.oem.key1",carrier_value);
    property_set("ro.product.ontim.version",fileContent);
    property_set("ro.vendor.product.version",fileContent);

    if (carrier_value == "retgb" || carrier_value == "tescogb" || carrier_value == "pluspl"
         || carrier_value == "playpl" || (carrier_value == "reteu" && carrier_ontim != "reteu_reteuse")) {
        prop_product_value = "bali_reteu";
        prop_carrier_value = "reteu";
        property_set(prop_amclient,prop_client_value);
        property_set(prop_msclient,prop_clientrev_value);
        property_set(prop_product,prop_product_value);
        property_set(prop_build_fingerprint,get_fingerprint_property(prop_product_value));
        property_set(prop_fingerprint,get_fingerprint_property(prop_product_value));
        property_set(prop_vendor_fingerprint,get_fingerprint_property(prop_product_value));
        property_set("persist.vendor.normal","1");//表示正常版本，非 VTS 版本，prop 正常设置.
    } else if (carrier_value == "amxbr" || carrier_value == "amxmx" || carrier_value == "amxco"|| carrier_value == "openmx"|| carrier_value == "amxla") {
        property_set(prop_amclient,prop_clientcountry_value);
        property_set(prop_msclient,prop_clientrevc_value);
    } else if (carrier_value == "attmx") {
        property_set(prop_msclient,prop_clientmx_value);
    } else if (carrier_value == "timbr") {
        property_set(prop_msclient,prop_clientbr_value);
    } else {
        property_set(prop_amclient,prop_client_value);
        property_set(prop_msclient,prop_clientrev_value);
    }

    property_set(prop_build_fullversion,get_version_property(prop_version_value));
    property_set(prop_build_customerid,prop_carrier_value);
}

bool changeSystemProperty(std::string key) {
    if (key == prop_product || key == prop_build_fingerprint
      || key == prop_fingerprint || key == prop_vendor_fingerprint || key == prop_carrier) {
        return true;
    }
    return false;
}

std::string get_fingerprint_property(std::string value) {
    std::string  buildFingerprint = android::base::GetProperty(prop_fingerprint, "");
    std::vector<std::string> fingerprint = android::base::Split(buildFingerprint, "/");
    fingerprint[1] = value;
    return android::base::Join(fingerprint, "/");
}

std::string get_version_property(std::string value) {
    std::string  product_locale_value = android::base::GetProperty(prop_product_locale, "");
    size_t  locale_position = product_locale_value.find("-");
    std::string  locale_value = product_locale_value.replace(locale_position,1,".");
    std::string  product_value = prop_product_value.append(1,'.');
    std::string  build_value = android::base::GetProperty(prop_build_id, "");
    std::string build_number_value = build_value.erase(0, 3).append(1,'.');
    value = "Blur_Version." + build_number_value + product_value + prop_carrier_value + "." + locale_value;
    return value;
}

}  // namespace init
} // namespace android

