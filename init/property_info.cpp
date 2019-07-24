
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


namespace android {
namespace init {

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
std::string prop_clienttmobile_value = "android-tmobile-{country}";
std::string prop_clientdt_value = "android-dt-{country}-revc";
std::string prop_product_value = "bali";


void set_system_properties(){
    std::string  carrier_ontim = android::base::GetProperty(prop_carrier_ontim, "");
    size_t position = carrier_ontim.find("_");
    std::string  carrier_value = carrier_ontim.substr(0, position);
    property_set(prop_carrier,carrier_value);
    if (carrier_value == "o2gb" || carrier_value == "retgb" || carrier_value == "tescogb" || carrier_value == "pluspl"
         || carrier_value == "playpl" || carrier_value == "reteu2" || carrier_ontim == "reteu_reteu") {
        prop_product_value = "bali_reteu";
        property_set(prop_amclient,prop_client_value);
        property_set(prop_msclient,prop_clientrev_value);
        property_set(prop_product,prop_product_value);
        property_set(prop_build_fingerprint,get_fingerprint_property(prop_product_value));
        property_set(prop_fingerprint,get_fingerprint_property(prop_product_value));
        property_set(prop_vendor_fingerprint,get_fingerprint_property(prop_product_value));
    } else if (carrier_value == "retru") {
        prop_product_value = "bali_retru";
        property_set(prop_amclient,prop_client_value);
        property_set(prop_msclient,prop_clientrev_value);
        property_set(prop_product,prop_product_value);
        property_set(prop_build_fingerprint,get_fingerprint_property(prop_product_value));
        property_set(prop_fingerprint,get_fingerprint_property(prop_product_value));
        property_set(prop_vendor_fingerprint,get_fingerprint_property(prop_product_value));

    } else if (carrier_value == "amxbr" || carrier_value == "amxcl" || carrier_value == "amxmx"
               || carrier_value == "amxpe" || carrier_value == "amxco") {
        property_set(prop_amclient,prop_clientcountry_value);
        property_set(prop_msclient,prop_clientrevc_value);
    } else if (carrier_value == "attmx") {
        property_set(prop_amclient," ");
        property_set(prop_msclient,prop_clientmx_value);
    } else if (carrier_value == "eegb") {
        prop_product_value = "bali_reteu";
        property_set(prop_amclient," ");
        property_set(prop_msclient,prop_clientuk_value);
        property_set(prop_product,prop_product_value);
        property_set(prop_build_fingerprint,get_fingerprint_property(prop_product_value));
        property_set(prop_fingerprint,get_fingerprint_property(prop_product_value));
        property_set(prop_vendor_fingerprint,get_fingerprint_property(prop_product_value));
    } else if (carrier_value == "dteu") {
        prop_product_value = "bali_reteu";
        property_set(prop_amclient,prop_clienttmobile_value);
        property_set(prop_msclient,prop_clientdt_value);
        property_set(prop_product,prop_product_value);
        property_set(prop_build_fingerprint,get_fingerprint_property(prop_product_value));
        property_set(prop_fingerprint,get_fingerprint_property(prop_product_value));
        property_set(prop_vendor_fingerprint,get_fingerprint_property(prop_product_value));
    } else {
        property_set(prop_amclient,prop_client_value);
        property_set(prop_msclient,prop_clientrev_value);
    }
}

bool changeSystemProperty(std::string key) {
    if (key == prop_product || key == prop_build_fingerprint
      || key == prop_fingerprint || key == prop_vendor_fingerprint) {
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

}  // namespace init
} // namespace android

