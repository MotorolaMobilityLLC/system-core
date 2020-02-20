
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
std::string prop_product_device = "ro.product.device";
std::string prop_build_fingerprint = "ro.bootimage.build.fingerprint";
std::string prop_fingerprint = "ro.build.fingerprint";
std::string prop_vendor_fingerprint = "ro.vendor.build.fingerprint";
std::string prop_product_fingerprint = "ro.product.build.fingerprint";
std::string prop_client_value = "android-motorola";
std::string prop_clientrev_value = "android-motorola-rev2";
std::string prop_clientcountry_value = "android-americamovil-{country}";
std::string prop_clientrevc_value = "android-americamovil-{country}-revc";
std::string prop_clientwindit_value = "android-h3g-{country}-revc";
std::string prop_clientmx_value = "android-attmexico-mx-revc";
std::string prop_clientuk_value = "android-ee-uk-revc";
std::string prop_clientbr_value = "android-tim-br-revc";
std::string prop_clientit_value = "android-tim-it-revc";
std::string prop_clientor_value = "android-orange-{country}-revc";
std::string prop_clienttmobile_value = "android-tmobile-{country}";
std::string prop_clientdt_value = "android-dt-{country}-revc";
std::string prop_product_value = "fiji";
std::string prop_carrier_value = "retail";
std::string prop_version_value;
std::string product_version_file = "/product/version.txt";
std::string elabel_version_file = "/elabel/version.txt";
std::string prop_amazon_partnerid = "ro.csc.amazon.partnerid";
std::string prop_build_name = "ro.build.name";
std::string prop_build_product = "ro.build.product";
std::string prop_product_board = "ro.product.board";
std::string prop_product_vendor_device = "ro.product.vendor.device";
std::string prop_product_vendor_name = "ro.product.vendor.name";
std::string prop_boot_bootloader = "ro.boot.bootloader";
std::string prop_bootloader = "ro.bootloader";
std::string prop_build_description = "ro.build.description";
std::string prop_build_flavor = "ro.build.flavor";

void set_system_properties(){
    std::ifstream stream_product(product_version_file);
    std::ifstream stream_elabel(elabel_version_file);
    std::stringstream fileStream_product;
    std::stringstream fileStream_elabel;
    fileStream_product << stream_product.rdbuf();
    fileStream_elabel << stream_elabel.rdbuf();
    std::string fileContent_product = fileStream_product.str().substr(0,3);
    std::string fileContent_elabel = fileStream_elabel.str().substr(0,3);
    std::string  carrier_ontim = android::base::GetProperty(prop_carrier_ontim, "");
    size_t position = carrier_ontim.find("_");
    std::string  carrier_value = carrier_ontim.substr(0, position);
    prop_product_value = android::base::GetProperty(prop_product, "");
    property_set(prop_carrier,carrier_value);
    property_set("ro.oem.key1",carrier_value);
    property_set("ro.product.ontim.version", fileContent_product);
    property_set("ro.vendor.product.version", fileContent_product);
    property_set("ro.elabel.ontim.version", fileContent_elabel);
    property_set("ro.vendor.elabel.version", fileContent_elabel);
    std::string  build_name = android::base::GetProperty(prop_build_name, "");

    if (prop_product_value == "fiji") {
        if(build_name == "lenovo") {
            prop_product_value = "fiji_lnv";
            property_set(prop_product_vendor_name, prop_product_value);
            property_set(prop_amclient, prop_client_value);
            property_set(prop_msclient, prop_clientrev_value);
            property_set(prop_product, prop_product_value);
            property_set(prop_build_fingerprint, get_fingerprint_property(prop_product_value));
            property_set(prop_fingerprint, get_fingerprint_property(prop_product_value));
            property_set(prop_vendor_fingerprint, get_fingerprint_property(prop_product_value));
            property_set(prop_product_fingerprint, get_fingerprint_property(prop_product_value));
            property_set("persist.vendor.normal", "1");//表示正常版本，非 VTS 版本，prop 正常设置.
            property_set(prop_build_fullversion, get_version_property(prop_version_value));
            property_set(prop_build_customerid, prop_carrier_value);
            return;
        }
        if (isProductNameFijiReteu(carrier_ontim)) {
            prop_product_value = "fiji_reteu";
            if (carrier_ontim == "eegb_uksl") {
                property_set(prop_msclient, prop_clientuk_value);
            } else if (carrier_ontim == "timit_timit") {
                property_set(prop_msclient, prop_clientit_value);
                property_set(prop_amazon_partnerid, carrier_value);
            } else if (carrier_ontim == "windit_windds") {
                property_set(prop_msclient, prop_clientwindit_value);
                property_set(prop_amazon_partnerid, "3it");
            } else {
                property_set(prop_amclient, prop_client_value);
                property_set(prop_msclient, prop_clientrev_value);
            }
        } else if (isProductNameFijiLnv(carrier_ontim)) {
            //remain this temporarily for requirement update
            if(build_name == "lenovo") {
                prop_product_value = "fiji_lnv";
            } else {
                prop_product_value = "fiji";
            }
            property_set(prop_amclient, prop_client_value);
            property_set(prop_msclient, prop_clientrev_value);
        } else {
            if (carrier_ontim == "amxbr_clarobr" || carrier_ontim == "amxmx_amxmx"
             || carrier_ontim == "amxmx_amxmxsl" || carrier_ontim == "openmx_retmx"
             || carrier_ontim == "amxpe_claro" || carrier_ontim == "amxcl_clarosl"
             || carrier_ontim == "amxar_amxar" || carrier_ontim == "amxla_amxlas"
             || carrier_ontim == "amxla_amxlag") {
                property_set(prop_amclient, prop_clientcountry_value);
                property_set(prop_msclient, prop_clientrevc_value);
            } else if (carrier_ontim == "attmx_attmx") {
                property_set(prop_msclient, prop_clientmx_value);
                property_set(prop_amazon_partnerid,carrier_value);
            } else if (carrier_ontim == "timbr_clarobr") {
                property_set(prop_msclient, prop_clientbr_value);
            } else {
                property_set(prop_amclient, prop_client_value);
                property_set(prop_msclient, prop_clientrev_value);
            }
        }
        property_set(prop_product_vendor_name, prop_product_value);
        property_set(prop_product, prop_product_value);
        property_set(prop_build_fingerprint, get_fingerprint_property(prop_product_value));
        property_set(prop_fingerprint, get_fingerprint_property(prop_product_value));
        property_set(prop_vendor_fingerprint, get_fingerprint_property(prop_product_value));
        property_set(prop_product_fingerprint, get_fingerprint_property(prop_product_value));
    } else if (prop_product_value == "blackjack" || prop_product_value == "blackjack_64") {
        property_set(prop_product_device, "blackjack");
        set_some_vendor_properties("blackjack");

        if(build_name == "lenovo") {
            prop_product_value = "blackjack_lnv";
            property_set(prop_product_vendor_name, prop_product_value);
            property_set(prop_amclient, prop_client_value);
            property_set(prop_msclient, prop_clientrev_value);
            property_set(prop_product, prop_product_value);
            property_set(prop_build_fingerprint, get_fingerprint_property(prop_product_value));
            property_set(prop_fingerprint, get_fingerprint_property(prop_product_value));
            property_set(prop_vendor_fingerprint, get_fingerprint_property(prop_product_value));
            property_set(prop_product_fingerprint, get_fingerprint_property(prop_product_value));
            property_set("persist.vendor.normal", "1");//表示正常版本，非 VTS 版本，prop 正常设置.
            property_set(prop_build_fullversion, get_version_property(prop_version_value));
            property_set(prop_build_customerid, prop_carrier_value);
            return;
        }

        if (isProductNameBlackjackReteu(carrier_ontim)) {
            prop_product_value = "blackjack_reteu";
            if (carrier_ontim == "timit_timit") {
                property_set(prop_msclient, prop_clientit_value);
            } else if (carrier_ontim == "windit_windds") {
                property_set(prop_msclient, prop_clientwindit_value);
            } else if (carrier_ontim == "dteu_dteu") {
                property_set(prop_amclient, prop_clienttmobile_value);
                property_set(prop_msclient, prop_clientdt_value);
            } else if (carrier_ontim == "reteu_reteuop") {
                property_set(prop_msclient, prop_clientor_value);
            } else if (carrier_ontim == "eegb_uksl") {
                property_set(prop_msclient, prop_clientuk_value);
            } else {
                property_set(prop_amclient, prop_client_value);
                property_set(prop_msclient, prop_clientrev_value);
            }
        } else if (isProductNameBlackjackLnv(carrier_ontim)) {
            //remain this temporarily for requirement update
            if(build_name == "lenovo") {
                prop_product_value = "blackjack_lnv";
            } else {
                prop_product_value = "blackjack";
            }
            property_set(prop_amclient, prop_client_value);
            property_set(prop_msclient, prop_clientrev_value);
        } else if (isProductNameBlackjackRetru(carrier_ontim)) {
            prop_product_value = "blackjack_retru";
            prop_carrier_value = "retru";
            property_set(prop_amclient, prop_client_value);
            property_set(prop_msclient, prop_clientrev_value);
        } else {
            prop_product_value = "blackjack";
            if (carrier_ontim == "openmx_retmx" || carrier_ontim == "amxmx_amxmx"
             || carrier_ontim == "amxmx_amxmxsl" || carrier_ontim == "amxpe_claro"
             || carrier_ontim == "amxco_claro" || carrier_ontim == "amxbr_clarobr"
             || carrier_ontim == "amxar_amxar" || carrier_ontim == "amxcl_clarosl"
             || carrier_ontim == "amxla_amxlas" || carrier_ontim == "amxla_amxlag") {
                property_set(prop_amclient, prop_clientcountry_value);
                property_set(prop_msclient, prop_clientrevc_value);
            } else if (carrier_ontim == "attmx_attmx") {
                property_set(prop_msclient, prop_clientmx_value);
            } else if (carrier_ontim == "timbr_clarobr") {
                property_set(prop_msclient, prop_clientbr_value);
            } else {
                property_set(prop_amclient, prop_client_value);
                property_set(prop_msclient, prop_clientrev_value);
            }
        }

        property_set(prop_product, prop_product_value);
        property_set(prop_build_fingerprint, get_fingerprint_property(prop_product_value));
        property_set(prop_fingerprint, get_fingerprint_property(prop_product_value));
        property_set(prop_vendor_fingerprint, get_fingerprint_property(prop_product_value));
        property_set(prop_product_fingerprint, get_fingerprint_property(prop_product_value));
        property_set(prop_product_vendor_name, prop_product_value);

        // BEGIN Ontim, maqing, 20/11/2019, EKBLACKJ-178 , St-result :PASS,[BJ][Europe Requirement][Fiji Features]FEATURE-5963
        if (carrier_ontim == "timit_timit") {
             property_set(prop_amazon_partnerid, carrier_value);
        }
        if (carrier_ontim == "windit_windds") {
             property_set(prop_amazon_partnerid, "3it");
        }
        if (carrier_ontim == "attmx_attmx") {
             property_set(prop_amazon_partnerid,carrier_value);
        }
        if (carrier_ontim == "retru_retru") {
              property_set("ro.product.locale","ru-RU");
        }

        // END EKBLACKJ-178
    }

    property_set("persist.vendor.normal", "1");//表示正常版本，非 VTS 版本，prop 正常设置.
    property_set(prop_build_fullversion, get_version_property(prop_version_value));
    property_set(prop_build_customerid, prop_carrier_value);
}

void set_some_vendor_properties(std::string prop_product_value) {

        property_set(prop_build_product, prop_product_value);
        property_set(prop_product_board, prop_product_value);
        property_set(prop_product_vendor_device, prop_product_value);
        property_set(prop_boot_bootloader, get_product_property(prop_boot_bootloader,prop_product_value));
        property_set(prop_bootloader, get_product_property(prop_bootloader,prop_product_value));
        property_set(prop_build_description, get_product_property(prop_build_description,prop_product_value));
        property_set(prop_build_flavor, get_product_property(prop_build_flavor,prop_product_value));

}

bool isProductNameFijiReteu(std::string carrier_ontim) {
    if (carrier_ontim == "retgb_retgbds") return true;
    if (carrier_ontim == "retgb_cpwds") return true;
    if (carrier_ontim == "eegb_uksl") return true;
    if (carrier_ontim == "o2gb_teluk") return true;
    if (carrier_ontim == "tescogb_tescogb") return true;
    if (carrier_ontim == "reteu_reteu") return true;
    if (carrier_ontim == "windit_windds") return true;
    if (carrier_ontim == "timit_timit") return true;
    if (carrier_ontim == "reteu_retfr") return true;
    return false;
}

bool isProductNameFijiLnv(std::string carrier_ontim) {
    if (carrier_ontim == "retapac_reteuuae") return true;
    if (carrier_ontim == "retapac_rettld") return true;
    return false;
}

bool isProductNameBlackjackReteu(std::string carrier_ontim) {
    if (carrier_ontim == "retgb_retgbds") return true;
    if (carrier_ontim == "retgb_cpwds") return true;
    if (carrier_ontim == "tescogb_tescogb") return true;
    if (carrier_ontim == "reteu_reteu") return true;
    if (carrier_ontim == "playpl_playpl") return true;
    if (carrier_ontim == "dteu_dteu") return true;
    if (carrier_ontim == "reteu_reteuop") return true;
    if (carrier_ontim == "openeu_pluspl") return true;
    if (carrier_ontim == "timit_timit") return true;
    if (carrier_ontim == "windit_windds") return true;
    if (carrier_ontim == "reteu_retfr") return true;
    if (carrier_ontim == "eegb_uksl") return true;
    if (carrier_ontim == "vfeu_vfeu") return true;
    if (carrier_ontim == "reteu_dtag") return true;
    return false;
}

bool isProductNameBlackjackLnv(std::string carrier_ontim) {
    if (carrier_ontim == "retapac_reteusa") return true;
    if (carrier_ontim == "retapac_reteuuae") return true;
    if (carrier_ontim == "retapac_rettld") return true;
    return false;
}

bool isProductNameBlackjackRetru(std::string carrier_ontim) {
    if (carrier_ontim == "retru_retru") return true;
    return false;
}

bool changeSystemProperty(std::string key) {
    if (key == prop_product || key == prop_build_fingerprint
      || key == prop_fingerprint || key == prop_vendor_fingerprint
      || key == prop_carrier || key == prop_product_device
      || key == prop_product_fingerprint || key == prop_build_product
      || key == prop_product_board || key == prop_product_vendor_device
      || key == prop_product_vendor_name || key == prop_boot_bootloader
      || key == prop_bootloader|| key == prop_build_description
      || key == prop_build_flavor) {
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

std::string get_product_property(std::string prop_name, std::string value) {
    std::string  product_name = android::base::GetProperty(prop_name, "");
    std::vector<std::string> product = android::base::Split(product_name, "-");
    product[0] = value;
    return android::base::Join(product, "-");
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

