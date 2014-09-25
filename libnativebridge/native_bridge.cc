/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include "nativebridge/native_bridge.h"

#include <cstring>
#include <cutils/log.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>


namespace android {

// Environment values required by the apps running with native bridge.
struct NativeBridgeRuntimeValues {
    const char* os_arch;
    const char* cpu_abi;
    const char* cpu_abi2;
    const char* *supported_abis;
    int32_t abi_count;
};

// The symbol name exposed by native-bridge with the type of NativeBridgeCallbacks.
static constexpr const char* kNativeBridgeInterfaceSymbol = "NativeBridgeItf";

enum class NativeBridgeState {
  kNotSetup,                        // Initial state.
  kOpened,                          // After successful dlopen.
  kInitialized,                     // After successful initialization.
  kClosed                           // Closed or errors.
};

static const char* kNotSetupString = "kNotSetup";
static const char* kOpenedString = "kOpened";
static const char* kInitializedString = "kInitialized";
static const char* kClosedString = "kClosed";

static const char* GetNativeBridgeStateString(NativeBridgeState state) {
  switch (state) {
    case NativeBridgeState::kNotSetup:
      return kNotSetupString;

    case NativeBridgeState::kOpened:
      return kOpenedString;

    case NativeBridgeState::kInitialized:
      return kInitializedString;

    case NativeBridgeState::kClosed:
      return kClosedString;
  }
}

// Current state of the native bridge.
static NativeBridgeState state = NativeBridgeState::kNotSetup;

// Whether we had an error at some point.
static bool had_error = false;

// Handle of the loaded library.
static void* native_bridge_handle = nullptr;
// Pointer to the callbacks. Available as soon as LoadNativeBridge succeeds, but only initialized
// later.
static NativeBridgeCallbacks* callbacks = nullptr;
// Callbacks provided by the environment to the bridge. Passed to LoadNativeBridge.
static const NativeBridgeRuntimeCallbacks* runtime_callbacks = nullptr;

// The app's data directory.
static char* app_data_dir = nullptr;

static constexpr uint32_t kNativeBridgeCallbackVersion = 1;

// Characters allowed in a native bridge filename. The first character must
// be in [a-zA-Z] (expected 'l' for "libx"). The rest must be in [a-zA-Z0-9._-].
static bool CharacterAllowed(char c, bool first) {
  if (first) {
    return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z');
  } else {
    return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') ||
           (c == '.') || (c == '_') || (c == '-');
  }
}

// We only allow simple names for the library. It is supposed to be a file in
// /system/lib or /vendor/lib. Only allow a small range of characters, that is
// names consisting of [a-zA-Z0-9._-] and starting with [a-zA-Z].
bool NativeBridgeNameAcceptable(const char* nb_library_filename) {
  const char* ptr = nb_library_filename;
  if (*ptr == 0) {
    // Emptry string. Allowed, means no native bridge.
    return true;
  } else {
    // First character must be [a-zA-Z].
    if (!CharacterAllowed(*ptr, true))  {
      // Found an invalid fist character, don't accept.
      ALOGE("Native bridge library %s has been rejected for first character %c", nb_library_filename, *ptr);
      return false;
    } else {
      // For the rest, be more liberal.
      ptr++;
      while (*ptr != 0) {
        if (!CharacterAllowed(*ptr, false)) {
          // Found an invalid character, don't accept.
          ALOGE("Native bridge library %s has been rejected for %c", nb_library_filename, *ptr);
          return false;
        }
        ptr++;
      }
    }
    return true;
  }
}

static bool VersionCheck(NativeBridgeCallbacks* cb) {
  return cb != nullptr && cb->version == kNativeBridgeCallbackVersion;
}

bool LoadNativeBridge(const char* nb_library_filename,
                      const NativeBridgeRuntimeCallbacks* runtime_cbs) {
  // We expect only one place that calls LoadNativeBridge: Runtime::Init. At that point we are not
  // multi-threaded, so we do not need locking here.

  if (state != NativeBridgeState::kNotSetup) {
    // Setup has been called before. Ignore this call.
    if (nb_library_filename != nullptr) {  // Avoids some log-spam for dalvikvm.
      ALOGW("Called LoadNativeBridge for an already set up native bridge. State is %s.",
            GetNativeBridgeStateString(state));
    }
    // Note: counts as an error, even though the bridge may be functional.
    had_error = true;
    return false;
  }

  if (nb_library_filename == nullptr || *nb_library_filename == 0) {
    state = NativeBridgeState::kClosed;
    return true;
  } else {
    if (!NativeBridgeNameAcceptable(nb_library_filename)) {
      state = NativeBridgeState::kClosed;
      had_error = true;
    } else {
      // Try to open the library.
      void* handle = dlopen(nb_library_filename, RTLD_LAZY);
      if (handle != nullptr) {
        callbacks = reinterpret_cast<NativeBridgeCallbacks*>(dlsym(handle,
                                                                   kNativeBridgeInterfaceSymbol));
        if (callbacks != nullptr) {
          if (VersionCheck(callbacks)) {
            // Store the handle for later.
            native_bridge_handle = handle;
          } else {
            callbacks = nullptr;
            dlclose(handle);
            ALOGW("Unsupported native bridge interface.");
          }
        } else {
          dlclose(handle);
        }
      }

      // Two failure conditions: could not find library (dlopen failed), or could not find native
      // bridge interface (dlsym failed). Both are an error and close the native bridge.
      if (callbacks == nullptr) {
        had_error = true;
        state = NativeBridgeState::kClosed;
      } else {
        runtime_callbacks = runtime_cbs;
        state = NativeBridgeState::kOpened;
      }
    }
    return state == NativeBridgeState::kOpened;
  }
}

#if defined(__arm__)
static const char* kRuntimeISA = "arm";
#elif defined(__aarch64__)
static const char* kRuntimeISA = "arm64";
#elif defined(__mips__)
static const char* kRuntimeISA = "mips";
#elif defined(__i386__)
static const char* kRuntimeISA = "x86";
#elif defined(__x86_64__)
static const char* kRuntimeISA = "x86_64";
#else
static const char* kRuntimeISA = "unknown";
#endif


bool NeedsNativeBridge(const char* instruction_set) {
  return strncmp(instruction_set, kRuntimeISA, strlen(kRuntimeISA)) != 0;
}

#ifdef __APPLE__
template<typename T> void UNUSED(const T&) {}
#endif

void PreInitializeNativeBridge(const char* app_data_dir_in, const char* instruction_set) {
  if (app_data_dir_in == nullptr) {
    return;
  }

  const size_t len = strlen(app_data_dir_in);
  // Make a copy for us.
  app_data_dir = new char[len];
  strncpy(app_data_dir, app_data_dir_in, len);

#ifndef __APPLE__
  if (instruction_set == nullptr) {
    return;
  }
  size_t isa_len = strlen(instruction_set);
  if (isa_len > 10) {
    // 10 is a loose upper bound on the currently known instruction sets (a tight bound is 7 for
    // x86_64 [including the trailing \0]). This is so we don't have to change here if there will
    // be another instruction set in the future.
    ALOGW("Instruction set %s is malformed, must be less than 10 characters.", instruction_set);
    return;
  }

  // Bind-mount /system/lib{,64}/<isa>/cpuinfo to /proc/cpuinfo. If the file does not exist, the
  // mount command will fail, so we safe the extra file existence check...
  char cpuinfo_path[1024];

  snprintf(cpuinfo_path, 1024, "/system/lib"
#ifdef __LP64__
  "64"
#endif
    "/%s/cpuinfo", instruction_set);

  // Bind-mount.
  if (TEMP_FAILURE_RETRY(mount("/proc/cpuinfo", cpuinfo_path, nullptr, MS_BIND, nullptr)) == -1) {
    ALOGW("Failed to bind-mount %s as /proc/cpuinfo: %d", cpuinfo_path, errno);
  }
#else
  UNUSED(instruction_set);
  ALOGW("Mac OS does not support bind-mounting. Host simulation of native bridge impossible.");
#endif
}

static void SetCpuAbi(JNIEnv* env, jclass build_class, const char* field, const char* value) {
  if (value != nullptr) {
    jfieldID field_id = env->GetStaticFieldID(build_class, field, "Ljava/lang/String;");
    if (field_id == nullptr) {
      env->ExceptionClear();
      ALOGW("Could not find %s field.", field);
      return;
    }

    jstring str = env->NewStringUTF(value);
    if (str == nullptr) {
      env->ExceptionClear();
      ALOGW("Could not create string %s.", value);
      return;
    }

    env->SetStaticObjectField(build_class, field_id, str);
  }
}

static void SetSupportedAbis(JNIEnv* env, jclass build_class, const char* field,
                             const char* *values, int32_t value_count) {
  if (value_count < 0) {
    return;
  }
  if (values == nullptr && value_count > 0) {
    ALOGW("More than zero values expected: %d.", value_count);
    return;
  }

  jfieldID field_id = env->GetStaticFieldID(build_class, field, "[Ljava/lang/String;");
  if (field_id != nullptr) {
    // Create the array.
    jobjectArray array = env->NewObjectArray(value_count, env->FindClass("java/lang/String"),
                                             nullptr);
    if (array == nullptr) {
      env->ExceptionClear();
      ALOGW("Could not create array.");
      return;
    }

    // Fill the array.
    for (int32_t i = 0; i < value_count; i++) {
      jstring str = env->NewStringUTF(values[i]);
      if (str == nullptr) {
        env->ExceptionClear();
        ALOGW("Could not create string %s.", values[i]);
        return;
      }

      env->SetObjectArrayElement(array, i, str);
    }

    env->SetStaticObjectField(build_class, field_id, array);
  } else {
    env->ExceptionClear();
    ALOGW("Could not find %s field.", field);
  }
}

// Set up the environment for the bridged app.
static void SetupEnvironment(NativeBridgeCallbacks* callbacks, JNIEnv* env, const char* isa) {
  // Need a JNIEnv* to do anything.
  if (env == nullptr) {
    ALOGW("No JNIEnv* to set up app environment.");
    return;
  }

  // Query the bridge for environment values.
  const struct NativeBridgeRuntimeValues* env_values = callbacks->getAppEnv(isa);
  if (env_values == nullptr) {
    return;
  }

  // Keep the JNIEnv clean.
  jint success = env->PushLocalFrame(16);  // That should be small and large enough.
  if (success < 0) {
    // Out of memory, really borked.
    ALOGW("Out of memory while setting up app environment.");
    env->ExceptionClear();
    return;
  }

  // Reset CPU_ABI & CPU_ABI2 to values required by the apps running with native bridge.
  if (env_values->cpu_abi != nullptr || env_values->cpu_abi2 != nullptr ||
      env_values->abi_count >= 0) {
    jclass bclass_id = env->FindClass("android/os/Build");
    if (bclass_id != nullptr) {
      SetCpuAbi(env, bclass_id, "CPU_ABI", env_values->cpu_abi);
      SetCpuAbi(env, bclass_id, "CPU_ABI2", env_values->cpu_abi2);

      SetSupportedAbis(env, bclass_id, "SUPPORTED_ABIS", env_values->supported_abis,
                       env_values->abi_count);
    } else {
      // For example in a host test environment.
      env->ExceptionClear();
      ALOGW("Could not find Build class.");
    }
  }

  if (env_values->os_arch != nullptr) {
    jclass sclass_id = env->FindClass("java/lang/System");
    if (sclass_id != nullptr) {
      jmethodID set_prop_id = env->GetStaticMethodID(sclass_id, "setProperty",
          "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
      if (set_prop_id != nullptr) {
        // Reset os.arch to the value reqired by the apps running with native bridge.
        env->CallStaticObjectMethod(sclass_id, set_prop_id, env->NewStringUTF("os.arch"),
            env->NewStringUTF(env_values->os_arch));
      } else {
        env->ExceptionClear();
        ALOGW("Could not find setProperty method.");
      }
    } else {
      env->ExceptionClear();
      ALOGW("Could not find System class.");
    }
  }

  // Make it pristine again.
  env->PopLocalFrame(nullptr);
}

bool InitializeNativeBridge(JNIEnv* env, const char* instruction_set) {
  // We expect only one place that calls InitializeNativeBridge: Runtime::DidForkFromZygote. At that
  // point we are not multi-threaded, so we do not need locking here.

  if (state == NativeBridgeState::kOpened) {
    // Try to initialize.
    if (callbacks->initialize(runtime_callbacks, app_data_dir, instruction_set)) {
      SetupEnvironment(callbacks, env, instruction_set);
      state = NativeBridgeState::kInitialized;
    } else {
      // Unload the library.
      dlclose(native_bridge_handle);
      had_error = true;
      state = NativeBridgeState::kClosed;
    }
  } else {
    had_error = true;
    state = NativeBridgeState::kClosed;
  }

  return state == NativeBridgeState::kInitialized;
}

void UnloadNativeBridge() {
  // We expect only one place that calls UnloadNativeBridge: Runtime::DidForkFromZygote. At that
  // point we are not multi-threaded, so we do not need locking here.

  switch(state) {
    case NativeBridgeState::kOpened:
    case NativeBridgeState::kInitialized:
      // Unload.
      dlclose(native_bridge_handle);
      break;

    case NativeBridgeState::kNotSetup:
      // Not even set up. Error.
      had_error = true;
      break;

    case NativeBridgeState::kClosed:
      // Ignore.
      break;
  }

  state = NativeBridgeState::kClosed;
}

bool NativeBridgeError() {
  return had_error;
}

bool NativeBridgeAvailable() {
  return state == NativeBridgeState::kOpened || state == NativeBridgeState::kInitialized;
}

bool NativeBridgeInitialized() {
  // Calls of this are supposed to happen in a state where the native bridge is stable, i.e., after
  // Runtime::DidForkFromZygote. In that case we do not need a lock.
  return state == NativeBridgeState::kInitialized;
}

void* NativeBridgeLoadLibrary(const char* libpath, int flag) {
  if (NativeBridgeInitialized()) {
    return callbacks->loadLibrary(libpath, flag);
  }
  return nullptr;
}

void* NativeBridgeGetTrampoline(void* handle, const char* name, const char* shorty,
                                uint32_t len) {
  if (NativeBridgeInitialized()) {
    return callbacks->getTrampoline(handle, name, shorty, len);
  }
  return nullptr;
}

bool NativeBridgeIsSupported(const char* libpath) {
  if (NativeBridgeInitialized()) {
    return callbacks->isSupported(libpath);
  }
  return false;
}

};  // namespace android
