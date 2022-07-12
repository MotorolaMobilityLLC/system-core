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
#include "clientid.cpp"
#include "fingerprint.cpp"
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <string>
#include <android-base/logging.h>
#include <android-base/file.h>
#include "cutils/log.h"
#include <fstream>
#include <sstream>
#include <iostream>

using android::base::ReadFileToString;

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
std::string prop_product_hardware_sku = "ro.boot.product.hardware.sku";
std::string prop_vendor_hardware_nfc = "ro.vendor.hardware.nfc";

bool change_ro_prop_flag=false;

void set_system_properties(){
    change_ro_prop_flag=true;

    set_version_property();
    set_carrier_brand_property();
    set_product_properties();
    set_properties_by_carrier();
    set_fingerprint_property();
    set_clientid_property();
    set_other_properties();
    set_amazon_partnerid();
    set_product_locale();

    change_ro_prop_flag=false;
}

void set_version_property() {
    // Set version
    std::ifstream stream_product(product_version_file);
    std::stringstream fileStream_product;
    fileStream_product << stream_product.rdbuf();
    std::string fileContent_product = fileStream_product.str().substr(0,3);
    InitPropertySet("ro.product.ontim.version", fileContent_product);
    InitPropertySet("ro.vendor.product.version", fileContent_product);
}

void set_carrier_brand_property() {
    // Set ro.carrier and ro.carrier.ontim
    std::string  carrier_ontim = android::base::GetProperty(prop_carrier_ontim, "");
    size_t position = carrier_ontim.find("_");
    size_t positionlast = carrier_ontim.find_last_of("_");

    if (position != positionlast)
    {
        std::string brand = carrier_ontim.substr(positionlast + 1,3);
        if (brand == "lnv")
        {
            InitPropertySet(prop_carrier_brand, "lnv");
            InitPropertySet(prop_product_brand, "Lenovo");
        }
        carrier_ontim = carrier_ontim.erase(positionlast,4);
        InitPropertySet(prop_carrier_ontim,carrier_ontim);
    }
    std::string  carrier_value = carrier_ontim.substr(0, position);
    InitPropertySet(prop_carrier,carrier_value);

    //initialize at fist time to persist.sys.vendor.carrier
    std::string vendor_carrier_value = android::base::GetProperty(prop_vendor_carrier, "");
    if (vendor_carrier_value.empty())
    {
        InitPropertySet(prop_vendor_carrier, carrier_value);
    }

    //Fully disable DuraSpeed service for all carriers in LATAM/Europe/Brazil, and only enable it for APEM.
    if(carrier_value == "retapac" || carrier_value == "vfau" || carrier_value == "optus")
    {
        InitPropertySet("persist.vendor.duraspeed.app.on","1");
        InitPropertySet("persist.vendor.duraspeed.support","1");
    } else {
        InitPropertySet("persist.vendor.duraspeed.app.on","0");
        InitPropertySet("persist.vendor.duraspeed.support","0");
    }
}

static void get_borag_product_value() {
    std::string  carrier_brand = android::base::GetProperty(prop_carrier_brand, "");
    std::string  carrier_ontim = android::base::GetProperty(prop_carrier_ontim, "");
    if (prop_product_value == "borag_retail") {
        std::string band_id_path = "/sys/hwinfo/band_id";
        int len = strlen("band_id=");
        std::string hw_sku;
        if (ReadFileToString(band_id_path, &hw_sku)){
            int totallen = android::base::Trim(hw_sku).length();
            if(totallen == 17){
                hw_sku = hw_sku.substr(len,9);
            } else {
                hw_sku = hw_sku.substr(len,8);
            }
        }
        if (hw_sku == "XT2239-6"){
            if (carrier_ontim == "teleu_eu"){
                prop_product_value = "borag_retail";
            } else {
                prop_product_value = "borag_retaile";
            }
        } else if (hw_sku == "XT2239-7"){
            if (carrier_ontim == "retru_ru"){
                prop_product_value = "borag_retailrn";
            } else if (carrier_ontim == "teleu_eu"){
                prop_product_value = "borag_retailn";
            } else {
                prop_product_value = "borag_retailen";
            }
        } else {
            prop_product_value = "borag_retail";
        }

        InitPropertySet(prop_product_display, "moto e22");

    }

    return;
}

static void get_bora2g_product_value() {
    std::string  carrier_brand = android::base::GetProperty(prop_carrier_brand, "");
    std::string  carrier_ontim = android::base::GetProperty(prop_carrier_ontim, "");
    if (prop_product_value == "borago_retail") {
        std::string band_id_path = "/sys/hwinfo/band_id";
        int len = strlen("band_id=");
        std::string hw_sku;
        if (ReadFileToString(band_id_path, &hw_sku)){
            int totallen = android::base::Trim(hw_sku).length();
            if(totallen == 17){
                hw_sku = hw_sku.substr(len,9);
            } else {
                hw_sku = hw_sku.substr(len,8);
            }
        }
        if (hw_sku == "XT2239-18"){
            if (carrier_ontim == "teleu_eu"){
                prop_product_value = "borago_retail";
            } else {
                prop_product_value = "borago_retaile";
            }
        } else if (hw_sku == "XT2239-16"){
            prop_product_value = "borago_retailbr";
        } else {
            prop_product_value = "borago_retail";
        }

        if (hw_sku == "XT2239-16"){
            InitPropertySet(prop_product_display, "moto e22");
            set_product_model("moto e22");
        } else {
            InitPropertySet(prop_product_display, "moto e22i");
        }
    }

    return;
}

void set_product_properties() {
    prop_product_value = android::base::GetProperty(prop_product, "");
    // Set other property for borag
    if (prop_product_value == "borag_retail")
    {
        set_product_device("borag");
        set_some_vendor_properties(prop_product_value);
        get_borag_product_value();
        set_product_name(prop_product_value);
    } else if (prop_product_value == "borago_retail")
    {
        set_product_device("borago");
        set_some_vendor_properties(prop_product_value);
        get_bora2g_product_value();
        set_product_name(prop_product_value);
    }

}

void set_properties_by_carrier() {
    std::string  carrier_value = android::base::GetProperty(prop_carrier, "");
    // Set ro.oem.key1
    InitPropertySet("ro.oem.key1", carrier_value);
}

static bool is_nfc_supported() {
    std::string hardware_sku = android::base::GetProperty(prop_product_hardware_sku, "");
    if (hardware_sku == "dsdsn") return true;
	if (hardware_sku == "ssn") return true;
    return false;
}

void set_other_properties() {
    InitPropertySet("persist.vendor.normal", "1"); //表示正常版本，非 VTS 版本，prop 正常设置.
    InitPropertySet(prop_build_fullversion, get_version_property());
    InitPropertySet(prop_build_customerid, prop_carrier_value);
    InitPropertySet(prop_vendor_locale, android::base::GetProperty(prop_product_locale, "en-US"));
	InitPropertySet(prop_vendor_hardware_nfc, is_nfc_supported() ? "true" : "false");
}

void set_amazon_partnerid(){
    std::string  carrier_ontim = android::base::GetProperty(prop_carrier_ontim, "");
    std::string  carrier_value = carrier_ontim.substr(0, carrier_ontim.find("_"));
    if (carrier_ontim == "timit_timit") {
        InitPropertySet(prop_amazon_partnerid, carrier_value);
    } else if (carrier_ontim == "windit_windds") {
        InitPropertySet(prop_amazon_partnerid, "3it");
    } else if (carrier_ontim == "attmx_attmx") {
        InitPropertySet(prop_amazon_partnerid,carrier_value);
    } else if (carrier_ontim == "vfau_vfau") {
        InitPropertySet(prop_amazon_partnerid,"vfau");
    }
}

void set_product_locale(){
    std::string  carrier_ontim = android::base::GetProperty(prop_carrier_ontim, "");
    if (carrier_ontim == "retru_retru") {
        InitPropertySet(prop_product_locale,"ru-RU");
    }
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
    android::base::SetProperty("ro.elabel.ontim.version", fileContent_elabel);
    android::base::SetProperty("ro.vendor.elabel.version", fileContent_elabel);
}

bool isUpdatableSystemProperty(std::string key) {
    if (key == prop_amazon_partnerid) return true;
    return false;
}

}  // namespace init
} // namespace android

