/*
 * SPDX-FileCopyrightText: 2016-2023 Unisoc (Shanghai) Technologies Co., Ltd
 * SPDX-License-Identifier: LicenseRef-Unisoc-General-1.0
 */

#ifndef UNI_TOMBSTONE_H_
#define UNI_TOMBSTONE_H_

#include <sys/stat.h>
#include <sys/un.h>

// Unisoc: add corefile limit
// AR.599.001689.006143.016390,AR.599.001689.006143.016388
// Bug 2190781, Bug 2190780
// class: add directly

bool check_corefile_limit();
int check_avail_space(int percent);

#endif
