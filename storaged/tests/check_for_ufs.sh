#!/system/bin/sh

# Copyright (C) 2025 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# This script is used to determine if an Android device is using UFS or eMMC.
# We consider using UFS to be a "success" (exit code 0), and using eMMC or
# other unexpected issues to be a "failure" (non-zero exit code).

# There is no universal straight-forward way to determine UFS vs. eMMC, so
# we use educated guesses.  Due to places where this script is used, we also
# need this to work without root access on the device.

# Our high level logic:
#
# Assume /dev/block/by-name/userdata is a symlink to /dev/block/USERDATA_BLOCK.
# - If USERDATA_BLOCK starts with "mmc", then this is eMMC.
#
# Assume /sys/class/block/USERDATA_BLOCK is a symlink to FULL_PATH.
# - If FULL_PATH contains "/host0/", this is UFS.
# - Otherwise, this is eMMC.
#
# If any of our assumptions don't hold (can't access/find certain paths),
# then we consider it a failure.
#
# Note that we don't expect to be able to access FULL_PATH without root.  But
# fortunately we don't need access, just the name.


# Exit codes
# LINT.IfChange
readonly USING_UFS=0  # Must be 0 to indicate non-error
readonly USING_EMMC=1
readonly SETUP_ISSUE=2
readonly INTERNAL_ERROR=3
# LINT.ThenChange(//cts/hostsidetests/edi/src/android/edi/cts/StorageIoInterfaceDeviceInfo.java)

# All of these shell commands are assumed to be on the device.
readonly REQUIRED_CMDS="readlink sed"

readonly USERDATA_BY_NAME="/dev/block/by-name/userdata"

# Global variables (I know, but it's shell, so this is easiest)
userdata_block="UNSET"
# "Return value" of get_symlink_path()
symlink_path_result="UNSET"


# The output of this script will be used by automated testing, and analyzed
# at scale.  As such, we want to normalize the output, and try to just have
# a single line to analyze.
function exit_script() {
  local exit_code=$1
  local message="$2"

  local prefix=""
  case ${exit_code} in
    ${USING_UFS}) prefix="UFS Detected";;
    ${USING_EMMC}) prefix="eMMC Detected";;
    ${SETUP_ISSUE}) prefix="ERROR";;
    ${INTERNAL_ERROR}) prefix="INTERNAL ERROR";;
    *)
      prefix="UNEXPECTED EXIT CODE (${exit_code})"
      exit_code=${INTERNAL_ERROR}
      ;;
  esac

  # LINT.IfChange
  echo "${prefix}: ${message}"
  # LINT.ThenChange(//cts/hostsidetests/edi/src/android/edi/cts/StorageIoInterfaceDeviceInfo.java)
  exit ${exit_code}
}

# Exit in failure if we lack commands this script needs.
function check_setup() {
  # We explicitly check for these commands, because if we're missing any,
  # this error message will be vastly easier to debug.
  local missing_cmds=""
  for cmd in ${REQUIRED_CMDS}; do
    if ! command -v "${cmd}" > /dev/null; then
      missing_cmds="${missing_cmds} ${cmd}"
    fi
  done

  if [ -n "${missing_cmds}" ]; then
    local msg="Missing at least one of the required binaries: ${missing_cmds}"
    exit_script ${SETUP_ISSUE} "${msg}"
  fi
}


# Populate the global "symlink_path_result" with the first level of what
# the given "symlink" points to.  Exit in error if we can't figure it out.
function get_symlink_path() {
  # Using global symlink_path_result

  local symlink="$1"

  # "-L" tests if the file is a symbolic link.  We perform this check first
  # to give a more specific error message to aid debugging.  Very notably,
  # we do not use "-e" to check existence here, because that will fail if
  # we don't have access permissions to the destination of the link.
  if [ ! -L ${symlink} ]; then
    local msg="Could not find/access symlink ${symlink}"
    exit_script ${SETUP_ISSUE} "${msg}"
  fi

  # Note we do not use "-e" here, as we don't expect to have (non-root)
  # access to the full resolution of some of our symlinks.
  symlink_path_result=`readlink ${symlink}`
  local readlink_result=$?

  if [ ${readlink_result} -ne 0 ]; then
    local msg="Failed 'readlink ${symlink}'"
    exit_script ${SETUP_ISSUE} "${msg}"
  fi
}


# Set the global variable userdata_block, or exit in failure if we can't.
function set_userdata_block {
  # Using globals userdata_block, symlink_path_result

  get_symlink_path "${USERDATA_BY_NAME}"

  # Remove the "/dev/block/" part.
  userdata_block=`echo ${symlink_path_result} | sed 's#/dev/block/##'`

  # Done using this global.
  symlink_path_result="UNSET"
}


# If the userdata block starts with "mmc", it's eMMC.
function exit_if_userdata_block_is_emmc {
  # Using global userdata_block

  case "${userdata_block}" in
     mmc*)
       local msg="userdata block is ${userdata_block}"
       exit_script ${USING_EMMC} "${msg}"
       ;;
  esac
}


# See if our userdata_block resolves to something under host0.
function check_for_userdata_block_within_host0 {
  # Using globals userdata_block, symlink_path_result

  get_symlink_path "/sys/class/block/${userdata_block}"

  case "${symlink_path_result}" in
    */host0/*)
      local msg="userdata ${userdata_block} is within host0"
      exit_script ${USING_UFS} "${msg}"
      ;;
  esac

  local msg="userdata ${userdata_block} is not within host0 (${symlink_path_result})"
  exit_script ${USING_EMMC} "${msg}"
}


check_setup

set_userdata_block
exit_if_userdata_block_is_emmc

# This function will exit, concluding either eMMC or UFS.
check_for_userdata_block_within_host0

exit_script ${INTERNAL_ERROR} "Unexpectedly at the end of the script file"
