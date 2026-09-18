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

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <interface/storage/storage.h>

#include "watchdog.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * is_data_checkpoint_active() - Check for an active, uncommitted checkpoint of
 * /data. If a checkpoint is active, storage should not commit any
 * rollback-protected writes to /data.
 * @active: Out parameter that will be set to the result of the check.
 *
 * Return: 0 if active was set and is valid, non-zero otherwise.
 */
int is_data_checkpoint_active(bool* active);

bool is_gsi_running();

/**
 * vold_connect() - Connect to android.system.vold.IVold.
 *
 * Return: 0 on success or a negative value if connecting failed.
 */
int vold_connect();

/**
 * checkpointing_get_state() - Respond to an incoming STORAGE_CHECKPOINTING_STATE request
 *
 * This function must not be called unless vold_connect() has successfully returned already.
 *
 * @msg: The incoming message with cmd set to STORAGE_CHECKPOINTING_STATE
 * @req: The message's request data. Unused because checkpointing state has no specific data.
 * @req_len: The length of the message's request data. Should be 0.
 * @watcher: Watcher used to track the request's progress.
 *
 * Return: 0 on success or a negative error code value on failure.
 */
int checkpointing_get_state(struct storage_msg* msg, const void* req, size_t req_len,
                            struct watcher* watcher);

#ifdef __cplusplus
}
#endif
