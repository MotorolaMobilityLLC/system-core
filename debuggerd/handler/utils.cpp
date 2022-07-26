/*
 * Copyright 2022 UNISOC Technologies Co.,Ltd.
 */

#define LOG_TAG "DEBUG"
#include <errno.h>
#include <sys/statvfs.h>
#include <log/log.h>

int check_corefile_limit()
{
  struct statvfs stat;
  if(statvfs("/data", &stat) == 0){
      //free blocks < 10% Total Blocks
      if (stat.f_bavail < (stat.f_blocks*10/100)) {
          ALOGE("No more space left  %ld, available blocks %ld , total is %ld \n",
            stat.f_bsize*stat.f_bavail, stat.f_bavail, stat.f_blocks);
          return -1;
      }
  }
  return 0;
}