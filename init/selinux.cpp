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

// This file contains the functions that initialize SELinux during boot as well as helper functions
// for SELinux operation for init.

// When the system boots, there is no SEPolicy present and init is running in the kernel domain.
// Init loads the SEPolicy from the file system, restores the context of /init based on this
// SEPolicy, and finally exec()'s itself to run in the proper domain.

// The SEPolicy on Android comes in two variants: monolithic and split.

// The monolithic policy variant is for legacy non-treble devices that contain a single SEPolicy
// file located at /sepolicy and is directly loaded into the kernel SELinux subsystem.

// The split policy is for supporting treble devices.  It splits the SEPolicy across files on
// /system/etc/selinux (the 'plat' portion of the policy) and /vendor/etc/selinux (the 'nonplat'
// portion of the policy).  This is necessary to allow the system image to be updated independently
// of the vendor image, while maintaining contributions from both partitions in the SEPolicy.  This
// is especially important for VTS testing, where the SEPolicy on the Google System Image may not be
// identical to the system image shipped on a vendor's device.

// The split SEPolicy is loaded as described below:
// 1) There is a precompiled SEPolicy located at /vendor/etc/selinux/precompiled_sepolicy.
//    Stored along with this file is the sha256 hash of the parts of the SEPolicy on /system that
//    were used to compile this precompiled policy.  The system partition contains a similar sha256
//    of the parts of the SEPolicy that it currently contains.  If these two hashes match, then the
//    system loads this precompiled_sepolicy directly.
// 2) If these hashes do not match, then /system has been updated out of sync with /vendor and the
//    init needs to compile the SEPolicy.  /system contains the SEPolicy compiler, secilc, and it
//    is used by the LoadSplitPolicy() function below to compile the SEPolicy to a temp directory
//    and load it.  That function contains even more documentation with the specific implementation
//    details of how the SEPolicy is compiled if needed.

#include "selinux.h"

#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <selinux/android.h>

#include "log.h"
#include "util.h"

using android::base::Timer;
using android::base::unique_fd;

namespace android {
namespace init {

namespace {

selabel_handle* sehandle = nullptr;

enum EnforcingStatus { SELINUX_PERMISSIVE, SELINUX_ENFORCING };

EnforcingStatus StatusFromCmdline() {
    EnforcingStatus status = SELINUX_ENFORCING;

    import_kernel_cmdline(false,
                          [&](const std::string& key, const std::string& value, bool in_qemu) {
                              if (key == "androidboot.selinux" && value == "permissive") {
                                  status = SELINUX_PERMISSIVE;
                              }
                          });

    return status;
}

bool IsEnforcing() {
    if (ALLOW_PERMISSIVE_SELINUX) {
        return StatusFromCmdline() == SELINUX_ENFORCING;
    }
    return true;
}

// Forks, executes the provided program in the child, and waits for the completion in the parent.
// Child's stderr is captured and logged using LOG(ERROR).
bool ForkExecveAndWaitForCompletion(const char* filename, char* const argv[]) {
    // Create a pipe used for redirecting child process's output.
    // * pipe_fds[0] is the FD the parent will use for reading.
    // * pipe_fds[1] is the FD the child will use for writing.
    int pipe_fds[2];
    if (pipe(pipe_fds) == -1) {
        PLOG(ERROR) << "Failed to create pipe";
        return false;
    }

    pid_t child_pid = fork();
    if (child_pid == -1) {
        PLOG(ERROR) << "Failed to fork for " << filename;
        return false;
    }

    if (child_pid == 0) {
        // fork succeeded -- this is executing in the child process

        // Close the pipe FD not used by this process
        close(pipe_fds[0]);

        // Redirect stderr to the pipe FD provided by the parent
        if (TEMP_FAILURE_RETRY(dup2(pipe_fds[1], STDERR_FILENO)) == -1) {
            PLOG(ERROR) << "Failed to redirect stderr of " << filename;
            _exit(127);
            return false;
        }
        close(pipe_fds[1]);

        if (execv(filename, argv) == -1) {
            PLOG(ERROR) << "Failed to execve " << filename;
            return false;
        }
        // Unreachable because execve will have succeeded and replaced this code
        // with child process's code.
        _exit(127);
        return false;
    } else {
        // fork succeeded -- this is executing in the original/parent process

        // Close the pipe FD not used by this process
        close(pipe_fds[1]);

        // Log the redirected output of the child process.
        // It's unfortunate that there's no standard way to obtain an istream for a file descriptor.
        // As a result, we're buffering all output and logging it in one go at the end of the
        // invocation, instead of logging it as it comes in.
        const int child_out_fd = pipe_fds[0];
        std::string child_output;
        if (!android::base::ReadFdToString(child_out_fd, &child_output)) {
            PLOG(ERROR) << "Failed to capture full output of " << filename;
        }
        close(child_out_fd);
        if (!child_output.empty()) {
            // Log captured output, line by line, because LOG expects to be invoked for each line
            std::istringstream in(child_output);
            std::string line;
            while (std::getline(in, line)) {
                LOG(ERROR) << filename << ": " << line;
            }
        }

        // Wait for child to terminate
        int status;
        if (TEMP_FAILURE_RETRY(waitpid(child_pid, &status, 0)) != child_pid) {
            PLOG(ERROR) << "Failed to wait for " << filename;
            return false;
        }

        if (WIFEXITED(status)) {
            int status_code = WEXITSTATUS(status);
            if (status_code == 0) {
                return true;
            } else {
                LOG(ERROR) << filename << " exited with status " << status_code;
            }
        } else if (WIFSIGNALED(status)) {
            LOG(ERROR) << filename << " killed by signal " << WTERMSIG(status);
        } else if (WIFSTOPPED(status)) {
            LOG(ERROR) << filename << " stopped by signal " << WSTOPSIG(status);
        } else {
            LOG(ERROR) << "waitpid for " << filename << " returned unexpected status: " << status;
        }

        return false;
    }
}

bool ReadFirstLine(const char* file, std::string* line) {
    line->clear();

    std::string contents;
    if (!android::base::ReadFileToString(file, &contents, true /* follow symlinks */)) {
        return false;
    }
    std::istringstream in(contents);
    std::getline(in, *line);
    return true;
}

bool FindPrecompiledSplitPolicy(std::string* file) {
    file->clear();
    // If there is an odm partition, precompiled_sepolicy will be in
    // odm/etc/selinux. Otherwise it will be in vendor/etc/selinux.
    static constexpr const char vendor_precompiled_sepolicy[] =
        "/vendor/etc/selinux/precompiled_sepolicy";
    static constexpr const char odm_precompiled_sepolicy[] =
        "/odm/etc/selinux/precompiled_sepolicy";
    if (access(odm_precompiled_sepolicy, R_OK) == 0) {
        *file = odm_precompiled_sepolicy;
    } else if (access(vendor_precompiled_sepolicy, R_OK) == 0) {
        *file = vendor_precompiled_sepolicy;
    } else {
        PLOG(INFO) << "No precompiled sepolicy";
        return false;
    }
    std::string actual_plat_id;
    if (!ReadFirstLine("/system/etc/selinux/plat_and_mapping_sepolicy.cil.sha256", &actual_plat_id)) {
        PLOG(INFO) << "Failed to read "
                      "/system/etc/selinux/plat_and_mapping_sepolicy.cil.sha256";
        return false;
    }

    std::string precompiled_plat_id;
    std::string precompiled_sha256 = *file + ".plat_and_mapping.sha256";
    if (!ReadFirstLine(precompiled_sha256.c_str(), &precompiled_plat_id)) {
        PLOG(INFO) << "Failed to read " << precompiled_sha256;
        file->clear();
        return false;
    }
    if ((actual_plat_id.empty()) || (actual_plat_id != precompiled_plat_id)) {
        file->clear();
        return false;
    }
    return true;
}

bool GetVendorMappingVersion(std::string* plat_vers) {
    if (!ReadFirstLine("/vendor/etc/selinux/plat_sepolicy_vers.txt", plat_vers)) {
        PLOG(ERROR) << "Failed to read /vendor/etc/selinux/plat_sepolicy_vers.txt";
        return false;
    }
    if (plat_vers->empty()) {
        LOG(ERROR) << "No version present in plat_sepolicy_vers.txt";
        return false;
    }
    return true;
}

constexpr const char plat_policy_cil_file[] = "/system/etc/selinux/plat_sepolicy.cil";

bool IsSplitPolicyDevice() {
    return access(plat_policy_cil_file, R_OK) != -1;
}

bool LoadSplitPolicy() {
    // IMPLEMENTATION NOTE: Split policy consists of three CIL files:
    // * platform -- policy needed due to logic contained in the system image,
    // * non-platform -- policy needed due to logic contained in the vendor image,
    // * mapping -- mapping policy which helps preserve forward-compatibility of non-platform policy
    //   with newer versions of platform policy.
    //
    // secilc is invoked to compile the above three policy files into a single monolithic policy
    // file. This file is then loaded into the kernel.

    // Load precompiled policy from vendor image, if a matching policy is found there. The policy
    // must match the platform policy on the system image.
    std::string precompiled_sepolicy_file;
    if (FindPrecompiledSplitPolicy(&precompiled_sepolicy_file)) {
        unique_fd fd(open(precompiled_sepolicy_file.c_str(), O_RDONLY | O_CLOEXEC | O_BINARY));
        if (fd != -1) {
            if (selinux_android_load_policy_from_fd(fd, precompiled_sepolicy_file.c_str()) < 0) {
                LOG(ERROR) << "Failed to load SELinux policy from " << precompiled_sepolicy_file;
                return false;
            }
            return true;
        }
    }
    // No suitable precompiled policy could be loaded

    LOG(INFO) << "Compiling SELinux policy";

    // Determine the highest policy language version supported by the kernel
    set_selinuxmnt("/sys/fs/selinux");
    int max_policy_version = security_policyvers();
    if (max_policy_version == -1) {
        PLOG(ERROR) << "Failed to determine highest policy version supported by kernel";
        return false;
    }

    // We store the output of the compilation on /dev because this is the most convenient tmpfs
    // storage mount available this early in the boot sequence.
    char compiled_sepolicy[] = "/dev/sepolicy.XXXXXX";
    unique_fd compiled_sepolicy_fd(mkostemp(compiled_sepolicy, O_CLOEXEC));
    if (compiled_sepolicy_fd < 0) {
        PLOG(ERROR) << "Failed to create temporary file " << compiled_sepolicy;
        return false;
    }

    // Determine which mapping file to include
    std::string vend_plat_vers;
    if (!GetVendorMappingVersion(&vend_plat_vers)) {
        return false;
    }
    std::string mapping_file("/system/etc/selinux/mapping/" + vend_plat_vers + ".cil");

    // vendor_sepolicy.cil and plat_pub_versioned.cil are the new design to replace
    // nonplat_sepolicy.cil.
    std::string plat_pub_versioned_cil_file("/vendor/etc/selinux/plat_pub_versioned.cil");
    std::string vendor_policy_cil_file("/vendor/etc/selinux/vendor_sepolicy.cil");

    if (access(vendor_policy_cil_file.c_str(), F_OK) == -1) {
        // For backward compatibility.
        // TODO: remove this after no device is using nonplat_sepolicy.cil.
        vendor_policy_cil_file = "/vendor/etc/selinux/nonplat_sepolicy.cil";
        plat_pub_versioned_cil_file.clear();
    } else if (access(plat_pub_versioned_cil_file.c_str(), F_OK) == -1) {
        LOG(ERROR) << "Missing " << plat_pub_versioned_cil_file;
        return false;
    }

    // odm_sepolicy.cil is default but optional.
    std::string odm_policy_cil_file("/odm/etc/selinux/odm_sepolicy.cil");
    if (access(odm_policy_cil_file.c_str(), F_OK) == -1) {
        odm_policy_cil_file.clear();
    }
    const std::string version_as_string = std::to_string(max_policy_version);

    // clang-format off
    std::vector<const char*> compile_args {
        "/system/bin/secilc",
        plat_policy_cil_file,
        "-m", "-M", "true", "-G", "-N",
        // Target the highest policy language version supported by the kernel
        "-c", version_as_string.c_str(),
        mapping_file.c_str(),
        "-o", compiled_sepolicy,
        // We don't care about file_contexts output by the compiler
        "-f", "/sys/fs/selinux/null",  // /dev/null is not yet available
    };
    // clang-format on

    if (!plat_pub_versioned_cil_file.empty()) {
        compile_args.push_back(plat_pub_versioned_cil_file.c_str());
    }
    if (!vendor_policy_cil_file.empty()) {
        compile_args.push_back(vendor_policy_cil_file.c_str());
    }
    if (!odm_policy_cil_file.empty()) {
        compile_args.push_back(odm_policy_cil_file.c_str());
    }
    compile_args.push_back(nullptr);

    if (!ForkExecveAndWaitForCompletion(compile_args[0], (char**)compile_args.data())) {
        unlink(compiled_sepolicy);
        return false;
    }
    unlink(compiled_sepolicy);

    LOG(INFO) << "Loading compiled SELinux policy";
    if (selinux_android_load_policy_from_fd(compiled_sepolicy_fd, compiled_sepolicy) < 0) {
        LOG(ERROR) << "Failed to load SELinux policy from " << compiled_sepolicy;
        return false;
    }

    return true;
}

bool LoadMonolithicPolicy() {
    LOG(VERBOSE) << "Loading SELinux policy from monolithic file";
    if (selinux_android_load_policy() < 0) {
        PLOG(ERROR) << "Failed to load monolithic SELinux policy";
        return false;
    }
    return true;
}

bool LoadPolicy() {
    return IsSplitPolicyDevice() ? LoadSplitPolicy() : LoadMonolithicPolicy();
}

}  // namespace

void SelinuxInitialize() {
    Timer t;

    LOG(INFO) << "Loading SELinux policy";
    if (!LoadPolicy()) {
        LOG(FATAL) << "Unable to load SELinux policy";
    }

    bool kernel_enforcing = (security_getenforce() == 1);
    bool is_enforcing = IsEnforcing();
    if (kernel_enforcing != is_enforcing) {
        if (security_setenforce(is_enforcing)) {
            PLOG(FATAL) << "security_setenforce(%s) failed" << (is_enforcing ? "true" : "false");
        }
    }

    if (auto result = WriteFile("/sys/fs/selinux/checkreqprot", "0"); !result) {
        LOG(FATAL) << "Unable to write to /sys/fs/selinux/checkreqprot: " << result.error();
    }

    // init's first stage can't set properties, so pass the time to the second stage.
    setenv("INIT_SELINUX_TOOK", std::to_string(t.duration().count()).c_str(), 1);
}

// The files and directories that were created before initial sepolicy load or
// files on ramdisk need to have their security context restored to the proper
// value. This must happen before /dev is populated by ueventd.
void SelinuxRestoreContext() {
    LOG(INFO) << "Running restorecon...";
    selinux_android_restorecon("/dev", 0);
    selinux_android_restorecon("/dev/kmsg", 0);
    if constexpr (WORLD_WRITABLE_KMSG) {
        selinux_android_restorecon("/dev/kmsg_debug", 0);
    }
    selinux_android_restorecon("/dev/socket", 0);
    selinux_android_restorecon("/dev/random", 0);
    selinux_android_restorecon("/dev/urandom", 0);
    selinux_android_restorecon("/dev/__properties__", 0);

    selinux_android_restorecon("/plat_file_contexts", 0);
    selinux_android_restorecon("/nonplat_file_contexts", 0);
    selinux_android_restorecon("/plat_property_contexts", 0);
    selinux_android_restorecon("/nonplat_property_contexts", 0);
    selinux_android_restorecon("/plat_seapp_contexts", 0);
    selinux_android_restorecon("/nonplat_seapp_contexts", 0);
    selinux_android_restorecon("/plat_service_contexts", 0);
    selinux_android_restorecon("/nonplat_service_contexts", 0);
    selinux_android_restorecon("/plat_hwservice_contexts", 0);
    selinux_android_restorecon("/nonplat_hwservice_contexts", 0);
    selinux_android_restorecon("/sepolicy", 0);
    selinux_android_restorecon("/vndservice_contexts", 0);

    selinux_android_restorecon("/dev/block", SELINUX_ANDROID_RESTORECON_RECURSE);
    selinux_android_restorecon("/dev/device-mapper", 0);

    selinux_android_restorecon("/sbin/mke2fs_static", 0);
    selinux_android_restorecon("/sbin/e2fsdroid_static", 0);
}

// This function sets up SELinux logging to be written to kmsg, to match init's logging.
void SelinuxSetupKernelLogging() {
    selinux_callback cb;
    cb.func_log = selinux_klog_callback;
    selinux_set_callback(SELINUX_CB_LOG, cb);
}

// selinux_android_file_context_handle() takes on the order of 10+ms to run, so we want to cache
// its value.  selinux_android_restorecon() also needs an sehandle for file context look up.  It
// will create and store its own copy, but selinux_android_set_sehandle() can be used to provide
// one, thus eliminating an extra call to selinux_android_file_context_handle().
void SelabelInitialize() {
    sehandle = selinux_android_file_context_handle();
    selinux_android_set_sehandle(sehandle);
}

// A C++ wrapper around selabel_lookup() using the cached sehandle.
// If sehandle is null, this returns success with an empty context.
bool SelabelLookupFileContext(const std::string& key, int type, std::string* result) {
    result->clear();

    if (!sehandle) return true;

    char* context;
    if (selabel_lookup(sehandle, &context, key.c_str(), type) != 0) {
        return false;
    }
    *result = context;
    free(context);
    return true;
}

// A C++ wrapper around selabel_lookup_best_match() using the cached sehandle.
// If sehandle is null, this returns success with an empty context.
bool SelabelLookupFileContextBestMatch(const std::string& key,
                                       const std::vector<std::string>& aliases, int type,
                                       std::string* result) {
    result->clear();

    if (!sehandle) return true;

    std::vector<const char*> c_aliases;
    for (const auto& alias : aliases) {
        c_aliases.emplace_back(alias.c_str());
    }
    c_aliases.emplace_back(nullptr);

    char* context;
    if (selabel_lookup_best_match(sehandle, &context, key.c_str(), &c_aliases[0], type) != 0) {
        return false;
    }
    *result = context;
    free(context);
    return true;
}

}  // namespace init
}  // namespace android
