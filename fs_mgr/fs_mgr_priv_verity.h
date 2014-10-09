/*
 * Copyright (C) 2013 The Android Open Source Project
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

#define FS_MGR_SETUP_VERITY_DISABLED -2
#define FS_MGR_SETUP_VERITY_FAIL -1
#define FS_MGR_SETUP_VERITY_SUCCESS 0
int fs_mgr_setup_verity(struct fstab_rec *fstab);
