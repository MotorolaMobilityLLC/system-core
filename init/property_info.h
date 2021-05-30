/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef _INIT_PROPERTY_INFO_H
#define _INIT_PROPERTY_INFO_H

#include <string>

namespace android {
namespace init {
bool isProductNameCyprusReteu(std::string carrier_ontim);
bool isProductNameCyprus64Reteu(std::string carrier_ontim);
bool isProductNameCyprus64Retru(std::string carrier_ontim);
std::string get_fingerprint_property_cyprus(std::string value);
std::string get_product_property(std::string prop_name,std::string value);
std::string get_version_property();
void set_system_properties();
bool changeSystemProperty(std::string key);
void set_product_name(std::string product_name);
void set_some_vendor_properties(std::string prop_product_value);
void set_fingerprint(std::string fingerprint) ;
void setElabelProperty();

}  // namespace init
}  // namespace android

#endif
