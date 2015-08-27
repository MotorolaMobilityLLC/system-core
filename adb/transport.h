/*
 * Copyright (C) 2011 The Android Open Source Project
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

#ifndef __TRANSPORT_H
#define __TRANSPORT_H

#include <sys/types.h>

#include <string>
#include <unordered_set>

#include "adb.h"

typedef std::unordered_set<std::string> FeatureSet;

const FeatureSet& supported_features();

class atransport {
public:
    // TODO(danalbert): We expose waaaaaaay too much stuff because this was
    // historically just a struct, but making the whole thing a more idiomatic
    // class in one go is a very large change. Given how bad our testing is,
    // it's better to do this piece by piece.

    atransport() {
        auth_fde = {};
        transport_fde = {};
        protocol_version = A_VERSION;
        max_payload = MAX_PAYLOAD;
    }

    virtual ~atransport() {}

    int (*read_from_remote)(apacket* p, atransport* t) = nullptr;
    int (*write_to_remote)(apacket* p, atransport* t) = nullptr;
    void (*close)(atransport* t) = nullptr;
    void (*kick)(atransport* t) = nullptr;

    int fd = -1;
    int transport_socket = -1;
    fdevent transport_fde;
    size_t ref_count = 0;
    uint32_t sync_token = 0;
    ConnectionState connection_state = kCsOffline;
    bool online = false;
    TransportType type = kTransportAny;

    // USB handle or socket fd as needed.
    usb_handle* usb = nullptr;
    int sfd = -1;

    // Used to identify transports for clients.
    char* serial = nullptr;
    char* product = nullptr;
    char* model = nullptr;
    char* device = nullptr;
    char* devpath = nullptr;
    int adb_port = -1;  // Use for emulators (local transport)
    bool kicked = false;

    // A list of adisconnect callbacks called when the transport is kicked.
    adisconnect disconnects = {};

    void* key = nullptr;
    unsigned char token[TOKEN_SIZE] = {};
    fdevent auth_fde;
    size_t failed_auth_attempts = 0;

    const char* connection_state_name() const;

    void update_version(int version, size_t payload);
    int get_protocol_version() const;
    size_t get_max_payload() const;

    inline const FeatureSet features() const {
        return features_;
    }

    bool has_feature(const std::string& feature) const;
    void add_feature(const std::string& feature);

    // Returns true if both we and the other end of the transport support the
    // feature.
    bool CanUseFeature(const std::string& feature) const;

private:
    // A set of features transmitted in the banner with the initial connection.
    // This is stored in the banner as 'features=feature0,feature1,etc'.
    FeatureSet features_;
    int protocol_version;
    size_t max_payload;

    DISALLOW_COPY_AND_ASSIGN(atransport);
};

/*
 * Obtain a transport from the available transports.
 * If state is != kCsAny, only transports in that state are considered.
 * If serial is non-NULL then only the device with that serial will be chosen.
 * If no suitable transport is found, error is set.
 */
atransport* acquire_one_transport(ConnectionState state, TransportType type,
                                  const char* serial, std::string* error_out);
void add_transport_disconnect(atransport* t, adisconnect* dis);
void remove_transport_disconnect(atransport* t, adisconnect* dis);
void kick_transport(atransport* t);
void run_transport_disconnects(atransport* t);
void update_transports(void);

void init_transport_registration(void);
std::string list_transports(bool long_listing);
atransport* find_transport(const char* serial);
void kick_all_tcp_devices();

void register_usb_transport(usb_handle* h, const char* serial,
                            const char* devpath, unsigned writeable);

/* cause new transports to be init'd and added to the list */
int register_socket_transport(int s, const char* serial, int port, int local);

// This should only be used for transports with connection_state == kCsNoPerm.
void unregister_usb_transport(usb_handle* usb);

int check_header(apacket* p, atransport* t);
int check_data(apacket* p);

/* for MacOS X cleanup */
void close_usb_devices();

void send_packet(apacket* p, atransport* t);

asocket* create_device_tracker(void);

#endif   /* __TRANSPORT_H */
