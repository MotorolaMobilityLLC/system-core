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

#ifndef __ADB_H
#define __ADB_H

#include <limits.h>
#include <stdint.h>
#include <sys/types.h>

#include <string>

#include <android-base/macros.h>

#include "adb_trace.h"
#include "fdevent/fdevent.h"
#include "socket.h"
#include "types.h"
#include "usb.h"

constexpr size_t MAX_PAYLOAD_V1 = 4 * 1024;
constexpr size_t MAX_PAYLOAD = 1024 * 1024;
constexpr size_t MAX_FRAMEWORK_PAYLOAD = 64 * 1024;

constexpr size_t LINUX_MAX_SOCKET_SIZE = 4194304;

#define A_SYNC 0x434e5953
#define A_CNXN 0x4e584e43
#define A_OPEN 0x4e45504f
#define A_OKAY 0x59414b4f
#define A_CLSE 0x45534c43
#define A_WRTE 0x45545257
#define A_AUTH 0x48545541
#define A_STLS 0x534C5453

// ADB protocol version.
// Version revision:
// 0x01000000: original
// 0x01000001: skip checksum (Dec 2017)
#define A_VERSION_MIN 0x01000000
#define A_VERSION_SKIP_CHECKSUM 0x01000001
#define A_VERSION 0x01000001

// Stream-based TLS protocol version
#define A_STLS_VERSION_MIN 0x01000000
#define A_STLS_VERSION 0x01000000

// Used for help/version information.
#define ADB_VERSION_MAJOR 1
#define ADB_VERSION_MINOR 0

std::string adb_version();

// Increment this when we want to force users to start a new adb server.
#define ADB_SERVER_VERSION 41

using TransportId = uint64_t;
class atransport;

uint32_t calculate_apacket_checksum(const apacket* packet);

/* the adisconnect structure is used to record a callback that
** will be called whenever a transport is disconnected (e.g. by the user)
** this should be used to cleanup objects that depend on the
** transport (e.g. remote sockets, listeners, etc...)
*/
struct adisconnect {
    void (*func)(void* opaque, atransport* t);
    void* opaque;
};

// A transport object models the connection to a remote device or emulator there
// is one transport per connected device/emulator. A "local transport" connects
// through TCP (for the emulator), while a "usb transport" through USB (for real
// devices).
//
// Note that kTransportHost doesn't really correspond to a real transport
// object, it's a special value used to indicate that a client wants to connect
// to a service implemented within the ADB server itself.
enum TransportType {
    kTransportUsb,
    kTransportLocal,
    kTransportAny,
    kTransportHost,
};

#define TOKEN_SIZE 20

enum ConnectionState {
    kCsAny = -1,

    kCsConnecting = 0,  // Haven't received a response from the device yet.
    kCsAuthorizing,     // Authorizing with keys from ADB_VENDOR_KEYS.
    kCsUnauthorized,    // ADB_VENDOR_KEYS exhausted, fell back to user prompt.
    kCsNoPerm,          // Insufficient permissions to communicate with the device.
    kCsOffline,

    kCsBootloader,
    kCsDevice,
    kCsHost,
    kCsRecovery,
    kCsSideload,
    kCsRescue,
};

inline bool ConnectionStateIsOnline(ConnectionState state) {
    switch (state) {
        case kCsBootloader:
        case kCsDevice:
        case kCsHost:
        case kCsRecovery:
        case kCsSideload:
        case kCsRescue:
            return true;
        default:
            return false;
    }
}

void print_packet(const char* label, apacket* p);

void handle_packet(apacket* p, atransport* t);

int launch_server(const std::string& socket_spec);
int adb_server_main(int is_daemon, const std::string& socket_spec, int ack_reply_fd);

/* initialize a transport object's func pointers and state */
int init_socket_transport(atransport* t, unique_fd s, int port, int local);
void init_usb_transport(atransport* t, usb_handle* usb);

std::string getEmulatorSerialString(int console_port);
#if ADB_HOST
atransport* find_emulator_transport_by_adb_port(int adb_port);
atransport* find_emulator_transport_by_console_port(int console_port);
#endif

unique_fd service_to_fd(std::string_view name, atransport* transport);
#if !ADB_HOST
unique_fd daemon_service_to_fd(std::string_view name, atransport* transport);
#endif

#if ADB_HOST
asocket* host_service_to_socket(std::string_view name, std::string_view serial,
                                TransportId transport_id);
#endif

#if !ADB_HOST
asocket* daemon_service_to_socket(std::string_view name);
#endif

#if !ADB_HOST
unique_fd execute_abb_command(std::string_view command);
#endif

#if !ADB_HOST
int init_jdwp(void);
asocket* create_jdwp_service_socket();
asocket* create_jdwp_tracker_service_socket();
unique_fd create_jdwp_connection_fd(int jdwp_pid);
#endif

bool handle_forward_request(const char* service, atransport* transport, int reply_fd);
bool handle_forward_request(const char* service,
                            std::function<atransport*(std::string* error)> transport_acquirer,
                            int reply_fd);

/* packet allocator */
apacket* get_apacket(void);
void put_apacket(apacket* p);

// Define it if you want to dump packets.
#define DEBUG_PACKETS 0

#if !DEBUG_PACKETS
#define print_packet(tag, p) \
    do {                     \
    } while (0)
#endif

#define DEFAULT_ADB_PORT 5037

#define DEFAULT_ADB_LOCAL_TRANSPORT_PORT 5555

#define ADB_CLASS 0xff
#define ADB_SUBCLASS 0x42
#define ADB_PROTOCOL 0x1

void local_init(const std::string& addr);
bool local_connect(int port);
int local_connect_arbitrary_ports(int console_port, int adb_port, std::string* error);

ConnectionState connection_state(atransport* t);

extern const char* adb_device_banner;

#define CHUNK_SIZE (64 * 1024)

// Argument delimeter for adb abb command.
#define ABB_ARG_DELIMETER ('\0')

#if !ADB_HOST
#define USB_FFS_ADB_PATH "/dev/usb-ffs/adb/"
#define USB_FFS_ADB_EP(x) USB_FFS_ADB_PATH #x

#define USB_FFS_ADB_EP0 USB_FFS_ADB_EP(ep0)
#define USB_FFS_ADB_OUT USB_FFS_ADB_EP(ep1)
#define USB_FFS_ADB_IN USB_FFS_ADB_EP(ep2)
#endif

enum class HostRequestResult {
    Handled,
    SwitchedTransport,
    Unhandled,
};

HostRequestResult handle_host_request(std::string_view service, TransportType type,
                                      const char* serial, TransportId transport_id, int reply_fd,
                                      asocket* s);

void handle_online(atransport* t);
void handle_offline(atransport* t);

void send_connect(atransport* t);
void send_tls_request(atransport* t);

void parse_banner(const std::string&, atransport* t);

// On startup, the adb server needs to wait until all of the connected devices are ready.
// To do this, we need to know when the scan has identified all of the potential new transports, and
// when each transport becomes ready.
// TODO: Do this for mDNS as well, instead of just USB?

// We've found all of the transports we potentially care about.
void adb_notify_device_scan_complete();

// One or more transports have changed status, check to see if we're ready.
void update_transport_status();

// Wait until device scan has completed and every transport is ready, or a timeout elapses.
void adb_wait_for_device_initialization();

#endif
