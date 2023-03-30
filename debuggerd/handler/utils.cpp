/*
 * SPDX-FileCopyrightText: 2016-2023 Unisoc (Shanghai) Technologies Co., Ltd
 * SPDX-License-Identifier: LicenseRef-Unisoc-General-1.0
 */

#define LOG_TAG "DEBUG"

#include <cutils/properties.h>
#include <errno.h>
#include <sys/statvfs.h>
#include <log/log.h>
#include <stdio.h>
#include <stdlib.h>
#include "debuggerd/utils.h"

// Unisoc: add corefile limit
// AR.599.001689.006143.016390,AR.599.001689.006143.016388
// Bug 2190781, Bug 2190780
// class: add directly

int check_avail_space(int percent)
{
  struct statvfs stat;
  if(statvfs("/data", &stat) == 0){
    //free blocks < percent of Total Blocks
    if (stat.f_bavail < (stat.f_blocks*percent/100)) {
      ALOGE("available space is less than %d, free_size: %ld , f_bavail: %ld, f_blocks: %ld \n",
          percent, stat.f_bsize*stat.f_bavail, stat.f_bavail, stat.f_blocks);
      return -1;
    }
  }
  return 0;
}

bool check_corefile_limit()
{
  if (getuid() > 10000) {
    char disable_app_coredump[PROPERTY_VALUE_MAX];
    property_get("persist.debug.disable_app_coredump", disable_app_coredump, "0");
    if (strcmp(disable_app_coredump, "1") == 0 || check_avail_space(50) != 0) {
      ALOGW("disable app coredump for uid: %d", getuid());
      return true;
    }
  }
  if(check_avail_space(10) != 0){
    return true;
  }
  return false;
}
