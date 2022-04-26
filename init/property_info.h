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

void set_system_properties();
void set_version_property();
void set_carrier_brand_property();
void set_product_properties();
void set_other_properties();
void set_properties_by_carrier();

extern bool change_ro_prop_flag;
bool isUpdatableSystemProperty(std::string key);
std::string get_version_property();
std::string get_product_property(std::string prop_name,std::string value);
void set_some_vendor_properties(std::string prop_product_value);

void set_product_model(std::string product_model);
void set_product_device(std::string product_device);
void set_product_name(std::string product_name);
void setElabelProperty();
}  // namespace init
}  // namespace android

#endif
