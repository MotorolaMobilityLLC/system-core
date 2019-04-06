#!/system/bin/sh
#
# Copyright (C) 2019 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Enforce fsverity signature checking
echo 1 > /proc/sys/fs/verity/require_signatures

# Load all keys
for cert in /product/etc/security/fsverity/*.der; do
  /system/bin/mini-keyctl padd asymmetric fsv_product .fs-verity < "$cert" ||
    log -p e -t fsverity_init "Failed to load $cert"
done

DEBUGGABLE=$(getprop ro.debuggable)
if [ $DEBUGGABLE != "1" ]; then
  # Prevent future key links to .fs-verity keyring
  /system/bin/mini-keyctl restrict_keyring .fs-verity ||
    log -p e -t fsverity_init "Failed to restrict .fs-verity keyring"
fi
