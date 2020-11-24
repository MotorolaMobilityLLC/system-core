
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
std::string prop_build_id = "ro.build.id";
std::string prop_carrier_ontim = "ro.carrier.ontim";
std::string prop_carrier = "ro.carrier";
std::string prop_amclient = "ro.com.google.clientidbase.am";
std::string prop_msclient = "ro.com.google.clientidbase.ms";
std::string prop_vsclient = "ro.com.google.clientidbase.vs";
std::string prop_fingerprint = "ro.build.fingerprint";
std::string prop_bootimage_fingerprint = "ro.bootimage.build.fingerprint";
std::string prop_system_fingerprint = "ro.system.build.fingerprint";
std::string prop_odm_fingerprint = "ro.odm.build.fingerprint";
std::string prop_vendor_fingerprint = "ro.vendor.build.fingerprint";
std::string prop_product_fingerprint = "ro.product.build.fingerprint";
std::string prop_build_name = "ro.build.name";
std::string prop_product_locale = "ro.product.locale";
std::string prop_product_name = "ro.product.name";
std::string prop_product_vendor_name = "ro.product.vendor.name";
std::string prop_product_odm_name = "ro.product.odm.name";
std::string prop_product_system_name = "ro.product.system.name";
std::string prop_product_product_name = "ro.product.product.name";
std::string prop_secure = "ro.secure";
std::string prop_adb_secure = "ro.adb.secure";
std::string prop_skip_setup_wizard = "ro.setupwizard.skip";
std::string prop_amazon_partnerid = "ro.csc.amazon.partnerid";

std::string prop_client_value = "android-motorola";
std::string prop_clientrvo3_value = "android-motorola-rvo3";
std::string prop_clientcountry_value = "android-americamovil-{country}";
std::string prop_clientrevc_value = "android-americamovil-{country}-revc";
std::string prop_clientmx_value = "android-attmexico-mx-revc";
std::string prop_clientuk_value = "android-ee-uk-revc";
std::string prop_clientbr_value = "android-tim-br-revc";
std::string prop_clientit_value = "android-tim-it-revc";
std::string prop_clientau_value = "android-optus-au-revc";
std::string prop_clientor_value = "android-orange-{country}-revc";
std::string prop_clientdt_value = "android-dt-{country}-revc";
std::string prop_cliento2_value = "android-tef-{country}-revc";
std::string prop_product_value = "fijisc";
std::string prop_carrier_value = "retail";

void set_system_properties() {
    prop_product_value = android::base::GetProperty(prop_product_name, "");
    std::string  build_name = android::base::GetProperty(prop_build_name, "");

    std::ifstream stream_product("/product/version.txt");
    std::stringstream fileStream_product;
    fileStream_product << stream_product.rdbuf();
    std::string fileContent_product = fileStream_product.str().substr(0,3);
    property_set("ro.product.ontim.version", fileContent_product);
    property_set("ro.vendor.product.version", fileContent_product);

    std::string  carrier_ontim = android::base::GetProperty(prop_carrier_ontim, "");
    size_t position = carrier_ontim.find("_");
    std::string  carrier_value = carrier_ontim.substr(0, position);
    property_set(prop_carrier, carrier_value);
    property_set("ro.oem.key1", carrier_value);
    property_set("persist.vendor.normal", "1");//表示正常版本，非 VTS 版本，prop 正常设置.

    //fijisc
    if(prop_product_value.find("fijisc") != std::string::npos) {
        if (isProductNameFijiReteu(carrier_ontim)) {
            prop_product_value = "fijisc_reteu";
            property_set(prop_amclient, prop_client_value);
            property_set(prop_msclient, prop_clientrvo3_value);
        } else {
            prop_product_value = "fijisc";
            if (carrier_ontim == "openmx_retmx" || carrier_ontim == "amxmx_amxmx"
             || carrier_ontim == "amxmx_amxmxsl" || carrier_ontim == "amxbr_clarobr") {
                property_set(prop_amclient, prop_clientcountry_value);
                property_set(prop_msclient, prop_clientrevc_value);
            } else if (carrier_ontim == "attmx_attmx") {
                property_set(prop_msclient, prop_clientmx_value);
            } else if (carrier_ontim == "timbr_timbr") {
                property_set(prop_msclient, prop_clientbr_value);
            } else {
                property_set(prop_amclient, prop_client_value);
                property_set(prop_msclient, prop_clientrvo3_value);
            }
        }

        set_product_name(prop_product_value);
        std::string fingerprint = get_fingerprint_property_fiji(prop_product_value);
        set_fingerprint(fingerprint);

        // BEGIN Ontim, maqing, 30/06/2020,EKMALTA-369:[Region_LATAM]FEATURE-5963: Amazon MDIP app single SKU solution
        if (carrier_ontim == "timit_timit") {
            property_set(prop_amazon_partnerid, carrier_value);
        }
        if (carrier_ontim == "windit_windds") {
            property_set(prop_amazon_partnerid, "3it");
        }
        if (carrier_ontim == "attmx_attmx") {
            property_set(prop_amazon_partnerid,carrier_value);
        }

        // END EKMALTA-369
        if (carrier_ontim == "retru_retru") {
            property_set("ro.product.locale","ru-RU");
        }
    //malta lite sc
    } else if(prop_product_value.find("maltalsc") != std::string::npos) {
        if(build_name == "lenovo") {
            if (carrier_ontim == "retru_retru") {
                prop_product_value = "maltalsc_lnvru";
            } else {
                prop_product_value = "maltalsc_lnv";
            }
            property_set(prop_amclient, prop_client_value);
            property_set(prop_msclient, prop_clientrvo3_value);
        } else {
            if (isProductNameMaltaLiteReteu(carrier_ontim)) {
                prop_product_value = "maltalsc_reteu";
                if (carrier_ontim == "timit_timit") {
                    property_set(prop_msclient, prop_clientit_value);
                    property_set(prop_vsclient, prop_clientit_value);
                } else {
                    property_set(prop_amclient, prop_client_value);
                    property_set(prop_msclient, prop_clientrvo3_value);
                }
            } else {
                prop_product_value = "maltalsc";
                if (carrier_ontim == "openmx_retmx" || carrier_ontim == "amxmx_amxmx"
                 || carrier_ontim == "amxmx_amxmxsl" || carrier_ontim == "amxpe_claro"
                 || carrier_ontim == "amxco_claro" || carrier_ontim == "amxla_amxlag"
                 || carrier_ontim == "amxcl_clarocl") {
                    property_set(prop_amclient, prop_clientcountry_value);
                    property_set(prop_msclient, prop_clientrevc_value);
                } else if (carrier_ontim == "attmx_attmx") {
                    property_set(prop_msclient, prop_clientmx_value);
                } else {
                    property_set(prop_amclient, prop_client_value);
                    property_set(prop_msclient, prop_clientrvo3_value);
                }
            }
        }

        set_product_name(prop_product_value);
        std::string fingerprint = get_fingerprint_property_maltalite(prop_product_value);
        set_fingerprint(fingerprint);

        // BEGIN Ontim, maqing, 30/06/2020,EKMALTA-369:[Region_LATAM]FEATURE-5963: Amazon MDIP app single SKU solution
        if (carrier_ontim == "timit_timit") {
             property_set(prop_amazon_partnerid, carrier_value);
        }
        if (carrier_ontim == "windit_windds") {
             property_set(prop_amazon_partnerid, "3it");
        }
        if (carrier_ontim == "attmx_attmx") {
             property_set(prop_amazon_partnerid,carrier_value);
        }

        // END EKMALTA-369
        if (carrier_ontim == "retru_retru") {
              property_set("ro.product.locale","ru-RU");
        }
    }

    property_set(prop_build_fullversion, get_version_property());
    property_set(prop_build_customerid, prop_carrier_value);
}

bool isProductNameFijiReteu(std::string carrier_ontim) {
    if (carrier_ontim == "reteu_reteu") return true;
    if (carrier_ontim == "reteu_retfr") return true;
    return false;
}

bool isProductNameMaltaLiteReteu(std::string carrier_ontim) {
    if (carrier_ontim == "retgb_retgbds") return true;
    if (carrier_ontim == "tescogb_tescogb") return true;
    if (carrier_ontim == "reteu_reteu") return true;
    if (carrier_ontim == "timit_timit") return true;
    if (carrier_ontim == "retgb_cpwds") return true;
    return false;
}

bool changeSystemProperty(std::string key) {
    if (key == prop_product_name || key == prop_carrier
      || key == prop_fingerprint || key == prop_vendor_fingerprint
      || key == prop_odm_fingerprint || key == prop_system_fingerprint
      || key == prop_product_fingerprint || key == prop_bootimage_fingerprint
      || key == prop_product_system_name || key == prop_product_odm_name
      || key == prop_product_product_name || key == prop_product_vendor_name
      || key == prop_product_locale || key == prop_skip_setup_wizard
      || key == prop_adb_secure || key == prop_secure) {
        return true;
    }
    return false;
}

void set_product_name(std::string product_name) {
    property_set(prop_product_name, product_name);
    property_set(prop_product_vendor_name, product_name);
    property_set(prop_product_system_name, product_name);
    property_set(prop_product_product_name, product_name);
    property_set(prop_product_odm_name, product_name);
}

void set_fingerprint(std::string fingerprint) {
    property_set(prop_bootimage_fingerprint, fingerprint);
    property_set(prop_fingerprint, fingerprint);
    property_set(prop_vendor_fingerprint, fingerprint);
    property_set(prop_product_fingerprint, fingerprint);
    property_set(prop_system_fingerprint, fingerprint);
    property_set(prop_odm_fingerprint, fingerprint);
}

std::string get_fingerprint_property_fiji(std::string value) {
    std::string  buildFingerprint = android::base::GetProperty(prop_system_fingerprint, "");
    std::vector<std::string> fingerprint = android::base::Split(buildFingerprint, ":");

    std::vector<std::string> name = android::base::Split(fingerprint[0], "/");
    name[1] = value;
    name[2] = "fijisc";
    fingerprint[0] = android::base::Join(name, "/");
    return android::base::Join(fingerprint, ":");
}

std::string get_fingerprint_property_maltalite(std::string value) {
    std::string  buildFingerprint = android::base::GetProperty(prop_system_fingerprint, "");
    std::vector<std::string> fingerprint = android::base::Split(buildFingerprint, ":");

    std::vector<std::string> name = android::base::Split(fingerprint[0], "/");
    name[1] = value;
    name[2] = "maltalsc";
    fingerprint[0] = android::base::Join(name, "/");
    return android::base::Join(fingerprint, ":");
}

std::string get_version_property() {
    std::string value;
    std::string  product_locale_value = android::base::GetProperty(prop_product_locale, "");
    size_t  locale_position = product_locale_value.find("-");
    std::string  locale_value = product_locale_value.replace(locale_position,1,".");
    std::string  product_value = prop_product_value.append(1,'.');
    std::string  build_value = android::base::GetProperty(prop_build_id, "");
    std::string build_number_value = build_value.erase(0, 3).append(1,'.');
    value = "Blur_Version." + build_number_value + product_value + prop_carrier_value + "." + locale_value;
    return value;
}

void setElabelProperty() {
    std::ifstream stream_elabel("/elabel/version.txt");
    std::stringstream fileStream_elabel;
    fileStream_elabel << stream_elabel.rdbuf();
    std::string fileContent_elabel = fileStream_elabel.str().substr(0,3);
    property_set("ro.elabel.ontim.version", fileContent_elabel);
    property_set("ro.vendor.elabel.version", fileContent_elabel);
}

}  // namespace init
} // namespace android

