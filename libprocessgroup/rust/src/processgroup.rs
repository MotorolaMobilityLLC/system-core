//
// Copyright (C) 2025 The Android Open-Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Bindings for Android's libprocessgroup

#![cfg(target_os = "android")]

use std::ffi::c_int;

use static_assertions::assert_type_eq_all;

assert_type_eq_all!(std::ffi::c_int, i32);
assert_type_eq_all!(libc::uid_t, u32);
assert_type_eq_all!(libc::pid_t, i32);

/// CGroup related functionality.
pub mod cgroup {
    /// Create a cgroup for the specified process
    pub fn create(uid: libc::uid_t, pid: libc::pid_t) -> Result<(), String> {
        let err = super::inner::createProcessGroup(uid, pid, false);

        if err >= 0 {
            Ok(())
        } else if err == -libc::EROFS {
            Err("Failed to create process group: Kernel missing support for cgroups".to_owned())
        } else {
            Err(format!("Failed to create process group: {err}"))
        }
    }

    /// Create a cgroup for use with `clone3` and `CLONE_INTO_CGROUP`
    pub fn create_for_clone_into(
        uid: libc::uid_t,
        zygote_pid: libc::pid_t,
        start_seq: u64,
    ) -> Result<(), String> {
        let res = super::inner::createCGroupForCloneInto(uid, zygote_pid, start_seq);

        if res == 0 {
            Ok(())
        } else {
            Err(format!("Failed to create a new cgroup for UID {uid}: {res}"))
        }
    }

    /// Provides the path for an attribute in a specific cgroup
    pub fn get_attribute_path_for_process(
        attr_name: &str,
        uid: libc::uid_t,
        pid: libc::pid_t,
    ) -> Result<Option<String>, &'static str> {
        let mut path = String::new();

        let err = super::inner::CgroupGetAttributePathForProcessRustBridge(
            attr_name, uid, pid, &mut path,
        );

        if err {
            Err("Failed to get attribute path for process")
        } else {
            Ok(path.is_empty().then_some(path))
        }
    }
}

/// Drop the FD cache for the cgroup path.
pub fn drop_task_profiles_resource_caching() {
    inner::DropTaskProfilesResourceCaching();
}

/// Return Ok if all processes were killed and the cgroup was successfully removed.
pub fn kill_process_group(
    uid: libc::uid_t,
    initial_pid: libc::pid_t,
    signal: c_int,
) -> Result<(), &'static str> {
    (inner::killProcessGroup(uid, initial_pid, signal) == 0)
        .then_some(())
        .ok_or("Failed to kill process group")
}

/// Set the profiles fora  given process.
pub fn set_process_profiles(
    uid: libc::uid_t,
    pid: libc::pid_t,
    profiles: &[&str],
) -> Result<(), &'static str> {
    inner::SetProcessProfilesRustBridge(uid, pid, profiles)
        .then_some(())
        .ok_or("Failed to set process profiles")
}

/// Set the task profiles for a given thread.
pub fn set_task_profiles(
    tid: libc::pid_t,
    profiles: &[&str],
    use_fd_cache: bool,
) -> Result<(), &'static str> {
    inner::SetTaskProfilesRustBridge(tid, profiles, use_fd_cache)
        .then_some(())
        .ok_or("Failed to set task profiles")
}

/// Bindings for Android's libprocessgroup's cgroup functionality.
#[cxx::bridge]
mod inner {
    unsafe extern "C++" {
        include!("processgroup/processgroup.h");
        include!("processgroup_rust_bridge/processgroup_rust_bridge.h");

        fn CgroupGetAttributePathForProcessRustBridge(
            attr_name: &str,
            uid: u32,
            pid: i32,
            path: &mut String,
        ) -> bool;

        fn createProcessGroup(uid: u32, pid: i32, memControl: bool) -> i32;

        fn createCGroupForCloneInto(uid: u32, zygote_pid: i32, start_seq: u64) -> i32;

        fn DropTaskProfilesResourceCaching();

        fn killProcessGroup(uid: u32, initial_pid: i32, signal: i32) -> i32;

        fn SetProcessProfilesRustBridge(uid: u32, pid: i32, profiles: &[&str]) -> bool;

        fn SetTaskProfilesRustBridge(tid: i32, profiles: &[&str], use_fd_cache: bool) -> bool;
    }
}
