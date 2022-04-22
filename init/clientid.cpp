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
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <map>
#include <android-base/logging.h>
#include <android-base/file.h>
#include "cutils/log.h"
#include <fstream>
#include <sstream>
#include <iostream>

std::map<std::string, std::string> get_clientid_map() {
    // Open txt file, txt file format should be: "carrier:clientidbase,clientidam,clientidms,clientidvs,"
    std::string clientid_file = "/product/etc/clientid.txt";
    std::map<std::string, std::string> carrier_clientid_map;
    std::ifstream clientid_stream;
    clientid_stream.open(clientid_file);
    if (!clientid_stream.is_open())
    {
        LOG(ERROR) << "Failed to open client id file: " << clientid_file;
        return carrier_clientid_map;
    }

    // Read txt by line and insert carrier/client string to map.
    std::string clientid_oneline;
    while (std::getline(clientid_stream, clientid_oneline))
    {
       if (clientid_oneline.empty()) continue;
       // Comment line, skip.
       if (android::base::StartsWith(clientid_oneline, "#")) continue;

       std::vector<std::string> clientidsplit = android::base::Split(clientid_oneline, ":");
       if (clientidsplit.size() < 2)
       {
           LOG(INFO) << "Please check the line in /product/etc/clientid.txt:\n" << clientid_oneline;
           continue;
       }

       carrier_clientid_map.insert(make_pair(android::base::Trim(clientidsplit[0]),
                                             android::base::Trim(clientidsplit[1])));
    }
    clientid_stream.close();
    return carrier_clientid_map;
}

void set_clientid_property() {
    std::map<std::string, std::string> carrier_clientid_map = get_clientid_map();
    std::string ro_carrier = android::base::GetProperty("ro.carrier", "");
    std::string clientid_string = "android-motorola,,android-motorola-rvo3,android-motorola-rvo3,";

    // If carrier is null or can't find client id from map, use default client id.
    if (!ro_carrier.empty() && carrier_clientid_map.count(ro_carrier) > 0)
    {
        clientid_string = carrier_clientid_map[ro_carrier];
    }
    LOG(INFO) << "ro.carrier: " << ro_carrier << "\n clientid_string:\n" << clientid_string;
    std::vector<std::string> allclientid = android::base::Split(clientid_string, ",");

    const int count = allclientid.size();
    LOG(INFO) << "allclientid.size: " << count;
    std::string properties_name[] =
    {
        "ro.com.google.clientidbase","ro.com.google.clientidbase.am",
        "ro.com.google.clientidbase.ms", "ro.com.google.clientidbase.vs",
        "ro.com.google.clientidbase.cr",
    };

    const int prop_count = sizeof(properties_name) / sizeof(std::string);

    for (int i = 0; i < prop_count; i++)
    {
        // Set property for each item in properties_name.
        // If clientid sub string does not exist, don't set property.
        if(allclientid[i]!="")
        android::init::InitPropertySet(properties_name[i], android::base::Trim(allclientid[i]));
    }
}
