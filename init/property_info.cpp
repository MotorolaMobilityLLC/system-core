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
std::string prop_vendor_locale = "ro.vendor.locale";
std::string prop_build_id = "ro.build.id";
std::string prop_carrier_ontim = "ro.carrier.ontim";
std::string prop_carrier_brand = "ro.carrier.brand";
std::string prop_carrier = "ro.carrier";
std::string prop_vendor_carrier = "persist.sys.vendor.carrier";
std::string prop_client = "ro.com.google.clientidbase";
std::string prop_amclient = "ro.com.google.clientidbase.am";
std::string prop_msclient = "ro.com.google.clientidbase.ms";
std::string prop_vsclient = "ro.com.google.clientidbase.vs";
std::string prop_fingerprint = "ro.build.fingerprint";
std::string prop_bootimage_fingerprint = "ro.bootimage.build.fingerprint";
std::string prop_system_fingerprint = "ro.system.build.fingerprint";
std::string prop_system_ext_fingerprint = "ro.system_ext.build.fingerprint";
std::string prop_odm_fingerprint = "ro.odm.build.fingerprint";
std::string prop_vendor_fingerprint = "ro.vendor.build.fingerprint";
std::string prop_product_fingerprint = "ro.product.build.fingerprint";
std::string prop_client_value = "android-motorola";
std::string prop_clientrev_value = "android-motorola-rev2";
std::string prop_clientrvo3_value = "android-motorola-rvo3";
std::string prop_clientcountry_value = "android-americamovil-{country}";
std::string prop_clientrevc_value = "android-americamovil-{country}-revc";
std::string prop_clientwindit_value = "android-h3g-{country}-revc";
std::string prop_clientmx_value = "android-attmexico-mx-rvc3";//
std::string prop_clientuk_value = "android-ee-uk-revc";
std::string prop_clientbr_value = "android-tim-br-revc";
std::string prop_clientit_value = "android-tim-it-revc";
std::string prop_clientau_value = "android-optus-au-revc";
std::string prop_clientvfam_value = "android-vf-au";
std::string prop_clientvf_value = "android-vf-au-rvc3";
std::string prop_clientcht_value = "android-cht-{country}-rvo3";
std::string prop_clientor_value = "android-orange-{country}-revc";
std::string prop_clienttmobile_value = "android-tmobile-{country}";
std::string prop_clientdt_value = "android-dt-{country}-revc";
std::string prop_cliento2_value = "android-tef-{country}-revc";//
std::string prop_product_value = "blackjack";
std::string prop_carrier_value = "retail";
std::string prop_version_value;
std::string product_version_file = "/product/version.txt";
std::string elabel_version_file = "/elabel/version.txt";
std::string prop_amazon_partnerid = "ro.csc.amazon.partnerid";
std::string prop_build_name = "ro.build.name";
std::string prop_build_product = "ro.build.product";
std::string prop_product_board = "ro.product.board";
std::string prop_product_brand = "ro.product.brand";
std::string prop_product_display = "ro.product.display";
std::string prop_product = "ro.product.name";
std::string prop_product_device = "ro.product.device";
std::string prop_product_vendor_device = "ro.product.vendor.device";
std::string prop_product_vendor_name = "ro.product.vendor.name";
std::string prop_product_odm_device = "ro.product.odm.device";
std::string prop_product_odm_name = "ro.product.odm.name";
std::string prop_product_system_device = "ro.product.system.device";
std::string prop_product_system_name = "ro.product.system.name";
std::string prop_product_system_ext_device = "ro.product.system_ext.device";
std::string prop_product_system_ext_name = "ro.product.system_ext.name";
std::string prop_product_product_device = "ro.product.product.device";
std::string prop_product_product_name = "ro.product.product.name";
std::string prop_boot_bootloader = "ro.boot.bootloader";
std::string prop_bootloader = "ro.bootloader";
std::string prop_build_description = "ro.build.description";
std::string prop_build_flavor = "ro.build.flavor";
std::string prop_secure = "ro.secure";
std::string prop_adb_secure = "ro.adb.secure";
std::string prop_skip_setup_wizard = "ro.setupwizard.skip";
std::string prop_product_model = "ro.product.model";
std::string prop_product_vendor_model = "ro.product.vendor.model";
std::string prop_product_system_model = "ro.product.system.model";
std::string prop_product_system_ext_model = "ro.product.system_ext.model";
std::string prop_product_odm_model = "ro.product.odm.model";
std::string prop_product_product_model = "ro.product.product.model";

bool change_ro_prop_flag=false;

void set_system_properties(){
    change_ro_prop_flag=true;
    std::ifstream stream_product(product_version_file);
    std::stringstream fileStream_product;
    fileStream_product << stream_product.rdbuf();
    std::string fileContent_product = fileStream_product.str().substr(0,3);
    std::string  carrier_ontim = android::base::GetProperty(prop_carrier_ontim, "");
    std::string vendor_carrier_value = android::base::GetProperty(prop_vendor_carrier, "");
    size_t position = carrier_ontim.find("_");
    size_t positionlast = carrier_ontim.find_last_of("_");
    if (position != positionlast){
        std::string  islnv = carrier_ontim.substr(positionlast + 1,3);
        if (islnv == "lnv"){
        InitPropertySet(prop_carrier_brand,"lnv");
        InitPropertySet(prop_product_brand,"Lenovo");
        }
        carrier_ontim = carrier_ontim.erase(positionlast,4);
        InitPropertySet(prop_carrier_ontim,carrier_ontim);
    }

    std::string  carrier_value = carrier_ontim.substr(0, position);
    prop_product_value = android::base::GetProperty(prop_product, "");
    std::string  carrier_brand = android::base::GetProperty(prop_carrier_brand, "");
    InitPropertySet(prop_carrier,carrier_value);
    InitPropertySet("ro.oem.key1",carrier_value);
    InitPropertySet(prop_client,"android-motorola");
    InitPropertySet("ro.product.ontim.version", fileContent_product);
    InitPropertySet("ro.vendor.product.version", fileContent_product);

    //initialize at fist time to persist.sys.vendor.carrier
    if (vendor_carrier_value.empty()) {
        InitPropertySet(prop_vendor_carrier, carrier_value);
    }

    //Fully disable DuraSpeed service for all carriers in LATAM/Europe/Brazil, and only enable it for APEM.
    if(carrier_value == "retapac" || carrier_value == "retin" || carrier_value == "optus") {
        InitPropertySet("persist.vendor.duraspeed.app.on","1");
        InitPropertySet("persist.vendor.duraspeed.support","1");
    } else {
        InitPropertySet("persist.vendor.duraspeed.app.on","0");
        InitPropertySet("persist.vendor.duraspeed.support","0");
    }

    //hawaii
    if (prop_product_value == "hawaii") {
        set_product_device("hawaii");
        set_some_vendor_properties("hawaii");

        if(carrier_brand == "lnv") {
            if (isProductNameHawaiiRetru(carrier_ontim)) {
                prop_product_value = "hawaii_retru_lnv";
            } else {
                prop_product_value = "hawaii_lnv";
            }
            InitPropertySet(prop_msclient, prop_clientrvo3_value);
            InitPropertySet(prop_vsclient, prop_clientrvo3_value);
            set_product_name(prop_product_value);

            std::string fingerprint = get_fingerprint_property_hawaii(prop_product_value);
            set_fingerprint(fingerprint);
            if (carrier_value == "retru") {
               InitPropertySet(prop_product_locale,"ru-RU");
              }
            InitPropertySet("persist.vendor.normal", "1");//表示正常版本，非 VTS 版本，prop 正常设置.
            InitPropertySet(prop_build_fullversion, get_version_property());
            InitPropertySet(prop_build_customerid, prop_carrier_value);
            InitPropertySet(prop_vendor_locale, android::base::GetProperty(prop_product_locale, "en-US"));
            return;
        }

        if (isProductNameHawaiiReteu(carrier_ontim)) {
            prop_product_value = "hawaii_reteu";
            InitPropertySet(prop_vsclient, prop_clientrvo3_value);
            InitPropertySet(prop_msclient, prop_clientrvo3_value);
        } else if (isProductNameHawaiiRetru(carrier_ontim)) {
            prop_product_value = "hawaii_retru";
            InitPropertySet(prop_vsclient, prop_clientrvo3_value);
            InitPropertySet(prop_msclient, prop_clientrvo3_value);
        } else {
            prop_product_value = "hawaii";
            if (carrier_ontim == "openmx_retmx" || carrier_ontim == "amxmx_amxmx"
             || carrier_ontim == "amxmx_amxmxsl" || carrier_ontim == "amxpe_claro"
             || carrier_ontim == "amxco_claro" || carrier_ontim == "amxbr_clarobr"
             || carrier_ontim == "amxla_amxlag") {
                InitPropertySet(prop_amclient, prop_clientcountry_value);
                InitPropertySet(prop_msclient, prop_clientrevc_value);
                InitPropertySet(prop_vsclient, prop_clientrevc_value);
            } else if (carrier_ontim == "attmx_attmx") {
                InitPropertySet(prop_msclient, prop_clientmx_value);
                InitPropertySet(prop_vsclient, prop_clientmx_value);
            } else if (carrier_ontim == "timbr_timbr") {
                InitPropertySet(prop_msclient, prop_clientbr_value);
                InitPropertySet(prop_vsclient, prop_clientbr_value);
            } else if (carrier_ontim == "vfau_vfau") {
                InitPropertySet(prop_amclient, prop_clientvfam_value);
                InitPropertySet(prop_msclient, prop_clientvf_value);
                InitPropertySet(prop_vsclient, prop_clientvf_value);
            } else {
                InitPropertySet(prop_msclient, prop_clientrvo3_value);
                InitPropertySet(prop_vsclient, prop_clientrvo3_value);
            }
        }

        set_product_name(prop_product_value);
        std::string fingerprint = get_fingerprint_property_hawaii(prop_product_value);
        set_fingerprint(fingerprint);

    }

    if (carrier_value == "timit") {
         InitPropertySet(prop_amazon_partnerid, carrier_value);
     } else if (carrier_value == "windit") {
         InitPropertySet(prop_amazon_partnerid, "3it");
     } else if (carrier_value == "attmx") {
         InitPropertySet(prop_amazon_partnerid,carrier_value);
     } else if (carrier_value == "vfau") {
         InitPropertySet(prop_amazon_partnerid,"vfau");
     } else if (carrier_value == "retru") {
        InitPropertySet(prop_product_locale,"ru-RU");
     }
    InitPropertySet("persist.vendor.normal", "1");//表示正常版本，非 VTS 版本，prop 正常设置.
    InitPropertySet(prop_build_fullversion, get_version_property());
    InitPropertySet(prop_build_customerid, prop_carrier_value);
    InitPropertySet(prop_vendor_locale, android::base::GetProperty(prop_product_locale, "en-US"));
    change_ro_prop_flag=false;
}

void set_some_vendor_properties(std::string prop_product_value) {
    InitPropertySet(prop_build_product, prop_product_value);
    InitPropertySet(prop_product_board, prop_product_value);
    InitPropertySet(prop_boot_bootloader, get_product_property(prop_boot_bootloader,prop_product_value));
    InitPropertySet(prop_bootloader, get_product_property(prop_bootloader,prop_product_value));
    InitPropertySet(prop_build_description, get_product_property(prop_build_description,prop_product_value));
    InitPropertySet(prop_build_flavor, get_product_property(prop_build_flavor,prop_product_value));
}

void set_product_model(std::string product_model) {
    InitPropertySet(prop_product_model, product_model);
    InitPropertySet(prop_product_vendor_model, product_model);
    InitPropertySet(prop_product_system_model, product_model);
    InitPropertySet(prop_product_system_ext_model, product_model);
    InitPropertySet(prop_product_product_model, product_model);
    InitPropertySet(prop_product_odm_model, product_model);
}

void set_product_name(std::string product_name) {
    InitPropertySet(prop_product, product_name);
    InitPropertySet(prop_product_vendor_name, product_name);
    InitPropertySet(prop_product_system_name, product_name);
    InitPropertySet(prop_product_system_ext_name, product_name);
    InitPropertySet(prop_product_product_name, product_name);
    InitPropertySet(prop_product_odm_name, product_name);
}

void set_product_device(std::string product_device) {
    InitPropertySet(prop_product_device, product_device);
    InitPropertySet(prop_product_vendor_device, product_device);
    InitPropertySet(prop_product_system_device, product_device);
    InitPropertySet(prop_product_system_ext_device, product_device);
    InitPropertySet(prop_product_odm_device, product_device);
    InitPropertySet(prop_product_product_device, product_device);
}

void set_fingerprint(std::string fingerprint) {
    InitPropertySet(prop_bootimage_fingerprint, fingerprint);
    InitPropertySet(prop_fingerprint, fingerprint);
    InitPropertySet(prop_vendor_fingerprint, fingerprint);
    InitPropertySet(prop_product_fingerprint, fingerprint);
    InitPropertySet(prop_system_fingerprint, fingerprint);
    InitPropertySet(prop_system_ext_fingerprint, fingerprint);
    InitPropertySet(prop_odm_fingerprint, fingerprint);
}

bool isProductNameHawaiiReteu(std::string carrier_ontim) {
    if (carrier_ontim == "reteu_reteu") return true;
    return false;
}


bool isProductNameHawaiiRetru(std::string carrier_ontim) {
    if (carrier_ontim == "retru_ru") return true;
    return false;
}


std::string get_fingerprint_property_hawaii(std::string value) {
    std::string  buildFingerprint = android::base::GetProperty(prop_fingerprint, "");
    std::string  brandvalue = android::base::GetProperty("ro.product.brand", "");
    std::vector<std::string> fingerprint = android::base::Split(buildFingerprint, ":");

    std::vector<std::string> name = android::base::Split(fingerprint[0], "/");
    name[0] = brandvalue;
    name[1] = value;
    name[2] = "hawaii";
    fingerprint[0] = android::base::Join(name, "/");
    return android::base::Join(fingerprint, ":");
}

std::string get_product_property(std::string prop_name, std::string value) {
    std::string  product_name = android::base::GetProperty(prop_name, "");
    std::vector<std::string> product = android::base::Split(product_name, "-");
    product[0] = value;
    return android::base::Join(product, "-");
}

std::string get_version_property() {
    std::string value;
    std::string  product_locale_value = android::base::GetProperty(prop_product_locale, "");
    size_t  locale_position = product_locale_value.find("-");
    std::string  locale_value = product_locale_value.erase(0,locale_position + 1);
    std::string  product_value = prop_product_value.append(1,'.');
    value = product_value + prop_carrier_value + "." + locale_value;
    return value;
}

void setElabelProperty() {
    std::ifstream stream_elabel(elabel_version_file);
    std::stringstream fileStream_elabel;
    fileStream_elabel << stream_elabel.rdbuf();
    std::string fileContent_elabel = fileStream_elabel.str().substr(0,3);
    InitPropertySet("ro.elabel.ontim.version", fileContent_elabel);
    InitPropertySet("ro.vendor.elabel.version", fileContent_elabel);
}

}  // namespace init
} // namespace android
