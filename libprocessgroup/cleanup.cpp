/*
 *  Copyright 2014 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
#include <string.h>
#include <unistd.h>

#include "processgroup_priv.h"

int main(int argc, char **argv)
{
    char buf[PATH_MAX];
    if (argc != 2)
        return -1;

    memcpy(buf, PROCESSGROUP_CGROUP_PATH, sizeof(PROCESSGROUP_CGROUP_PATH));
    strlcat(buf, argv[1], sizeof(buf));
    return rmdir(buf);
}
