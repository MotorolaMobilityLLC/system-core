/*
 * Copyright (C) 2012-2014 The Android Open Source Project
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

#define LOG_TAG "DEBUG"
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <sys/un.h>
#include <sys/statvfs.h>

#include <log/log.h>

#define MAX_COREDUMPS   4
#define COREDUMP_DATA_DIR      "/data/corefile"

static char s_coredump_dir[64] = COREDUMP_DATA_DIR;

int check_corefile_limit()
{
  DIR *d;
  struct dirent *de;
  struct statvfs stat;
  int cur_core_count = 0;

  d = opendir(s_coredump_dir);
  if (d == NULL)
  {
      return 1; //open dir filed ,so did not creat maps file.
  }

  while ((de = readdir(d)) != NULL)
  {
       /* Ignore "." and ".." */
       if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
        {
            continue;
        }

       if( !strncmp(de->d_name, "core", 4))    //only match core-xx
       {
            cur_core_count++;
       }
  }
  closedir(d);
  if(statvfs("/data", &stat) == 0){
      //free blocks < 10% Total Blocks
      if (stat.f_bavail < (stat.f_blocks*10/100)) {
          ALOGE("No more space left  %ld, available blocks %ld , total is %ld \n",stat.f_bsize*stat.f_bavail, stat.f_bavail, stat.f_blocks);
          return -2;
      }
  } else {
      ALOGE("STATVFS ERROR %s", strerror(errno));
      if(cur_core_count >= MAX_COREDUMPS) {
          ALOGE("Corefile is over limited");
          return -1;
      }
      return 1;
  }
  return 0;
}

