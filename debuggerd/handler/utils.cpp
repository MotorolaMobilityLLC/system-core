/*
 * Copyright 2022 UNISOC Technologies Co.,Ltd.
 */

#define LOG_TAG "DEBUG"
#include <errno.h>
#include <sys/statvfs.h>
#include <log/log.h>

int check_avail_space(int percent)
{
  struct statvfs stat;
  if(statvfs("/data", &stat) == 0){
      //free blocks < percent * Total Blocks
      if (stat.f_bavail < (stat.f_blocks*percent/100)) {
          ALOGE("available space is less than: %d, free_size: %ld, f_bavail: %ld , f_blocks: %ld \n",
            percent, stat.f_bsize*stat.f_bavail, stat.f_bavail, stat.f_blocks);
          return -1;
      }
  }
  return 0;
}