/*
 * Copyright 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <bionic/reserved_signals.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/system_properties.h>
#include <sys/types.h>

#ifdef MSSI_HAVE_AEE_FEATURE
#include <android-base/parseint.h>
#include <async_safe/log.h>
#endif

__BEGIN_DECLS

// Forward declare these classes so not everyone has to include GWP-ASan
// headers.
namespace gwp_asan {
struct AllocatorState;
struct AllocationMetadata;
};  // namespace gwp_asan

struct crash_detail_page_t;

// When updating this data structure, CrashInfoDataDynamic and the code in
// ReadCrashInfo() must also be updated.
struct __attribute__((packed)) debugger_process_info {
  void* abort_msg;
  void* fdsan_table;
  const gwp_asan::AllocatorState* gwp_asan_state;
  const gwp_asan::AllocationMetadata* gwp_asan_metadata;
  const char* scudo_stack_depot;
  const char* scudo_region_info;
  const char* scudo_ring_buffer;
  size_t scudo_ring_buffer_size;
  size_t scudo_stack_depot_size;
  bool recoverable_crash;
  struct crash_detail_page_t* crash_detail_page;
};

// GWP-ASan calbacks to support the recoverable mode. Separate from the
// debuggerd_callbacks_t because these values aren't available at debuggerd_init
// time, and have to be synthesized on request.
typedef struct {
  bool (*debuggerd_needs_gwp_asan_recovery)(void* fault_addr);
  void (*debuggerd_gwp_asan_pre_crash_report)(void* fault_addr);
  void (*debuggerd_gwp_asan_post_crash_report)(void* fault_addr);
} gwp_asan_callbacks_t;

// These callbacks are called in a signal handler, and thus must be async signal safe.
// If null, the callbacks will not be called.
typedef struct {
  debugger_process_info (*get_process_info)();
  gwp_asan_callbacks_t (*get_gwp_asan_callbacks)();
  void (*post_dump)();
} debuggerd_callbacks_t;

void debuggerd_init(debuggerd_callbacks_t* callbacks);
bool debuggerd_handle_signal(int signal_number, siginfo_t* info, void* context);

// DEBUGGER_ACTION_DUMP_TOMBSTONE and DEBUGGER_ACTION_DUMP_BACKTRACE are both
// triggered via BIONIC_SIGNAL_DEBUGGER. The debugger_action_t is sent via si_value
// using sigqueue(2) or equivalent. If no si_value is specified (e.g. if the
// signal is sent by kill(2)), the default behavior is to print the backtrace
// to the log.
#define DEBUGGER_SIGNAL BIONIC_SIGNAL_DEBUGGER

#ifdef MSSI_HAVE_AEE_FEATURE
static bool aee_parse_uint_with_error_reporting(const char* s, const char* name, int* v) {
  if (android::base::ParseInt(s, v) && *v >= 0) {
    return true;
  }
  (void)name;
  return false;
}

// We cannot use base::GetIntProperty, because that internally uses
// std::string, which allocates.
static bool aee_property_parse_int(const char* name, int* out) {
  const prop_info* pi = __system_property_find(name);
  if (!pi) return false;
  struct cookie_t {
    int* out;
    bool empty;
  } cookie{out, true};
  __system_property_read_callback(
      pi,
      [](void* raw_cookie, const char* name, const char* value, uint32_t) {
        // Property is set to empty value, ignoring.
        if (!*value) return;
        cookie_t* cookie = reinterpret_cast<cookie_t*>(raw_cookie);
        if (aee_parse_uint_with_error_reporting(value, name, cookie->out)) cookie->empty = false;
      },
      &cookie);
  return !cookie.empty;
}
#endif

static void __attribute__((__unused__)) debuggerd_register_handlers(struct sigaction* action) {
  bool enabled = true;
#if ANDROID_DEBUGGABLE
#ifdef MSSI_HAVE_AEE_FEATURE
  int api_level;
  char value[PROP_VALUE_MAX] = "";
  if (aee_property_parse_int("ro.vendor.api_level", &api_level)) {
    if (api_level <= 202404) {
      enabled = !(__system_property_get("debug.debuggerd.disable", value) > 0 && !strcmp(value, "1"));
    }
  }
#else //MSSI_HAVE_AEE_FEATURE
  char value[PROP_VALUE_MAX] = "";
  enabled = !(__system_property_get("debug.debuggerd.disable", value) > 0 && !strcmp(value, "1"));
#endif
#endif
  if (enabled) {
    sigaction(SIGABRT, action, nullptr);
    sigaction(SIGBUS, action, nullptr);
    sigaction(SIGFPE, action, nullptr);
    sigaction(SIGILL, action, nullptr);
    sigaction(SIGSEGV, action, nullptr);
    sigaction(SIGSTKFLT, action, nullptr);
    sigaction(SIGSYS, action, nullptr);
    sigaction(SIGTRAP, action, nullptr);
  }

  sigaction(BIONIC_SIGNAL_DEBUGGER, action, nullptr);
}

__END_DECLS
