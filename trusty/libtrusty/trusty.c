/*
 * Copyright (C) 2015 The Android Open Source Project
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

#define LOG_TAG "libtrusty"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <log/log.h>

#include "tipc_ioctl.h"

int tipc_connect(const char *dev_name, const char *srv_name)
{
	int fd;
	int rc;

	fd = open(dev_name, O_RDWR);
	if (fd < 0) {
		rc = -errno;
		ALOGE("%s: cannot open tipc device \"%s\": %s\n",
		      __func__, dev_name, strerror(errno));
		return rc < 0 ? rc : -1;
	}

	rc = ioctl(fd, TIPC_IOC_CONNECT, srv_name);
	if (rc < 0) {
		rc = -errno;
		ALOGE("%s: can't connect to tipc service \"%s\" (err=%d)\n",
		      __func__, srv_name, errno);
		close(fd);
		return rc < 0 ? rc : -1;
	}

	ALOGV("%s: connected to \"%s\" fd %d\n", __func__, srv_name, fd);
	return fd;
}

void tipc_close(int fd)
{
	close(fd);
}
