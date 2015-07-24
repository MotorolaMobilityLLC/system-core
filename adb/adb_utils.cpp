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

#define TRACE_TAG TRACE_ADB

#include "adb_utils.h"

#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>

#include <base/logging.h>
#include <base/stringprintf.h>
#include <base/strings.h>
#include <cutils/sockets.h>

#include "adb_trace.h"
#include "sysdeps.h"

#if defined(_WIN32)
#include <ws2tcpip.h>
#else
#include <netdb.h>
#endif

bool getcwd(std::string* s) {
  char* cwd = getcwd(nullptr, 0);
  if (cwd != nullptr) *s = cwd;
  free(cwd);
  return (cwd != nullptr);
}

bool directory_exists(const std::string& path) {
  struct stat sb;
  return lstat(path.c_str(), &sb) != -1 && S_ISDIR(sb.st_mode);
}

std::string escape_arg(const std::string& s) {
  std::string result = s;

  // Escape any ' in the string (before we single-quote the whole thing).
  // The correct way to do this for the shell is to replace ' with '\'' --- that is,
  // close the existing single-quoted string, escape a single single-quote, and start
  // a new single-quoted string. Like the C preprocessor, the shell will concatenate
  // these pieces into one string.
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '\'') {
      result.insert(i, "'\\'");
      i += 2;
    }
  }

  // Prefix and suffix the whole string with '.
  result.insert(result.begin(), '\'');
  result.push_back('\'');
  return result;
}

int mkdirs(const char *path)
{
    int ret;
    char *x = (char *)path + 1;

    for(;;) {
        x = adb_dirstart(x);
        if(x == 0) return 0;
        *x = 0;
        ret = adb_mkdir(path, 0775);
        *x = OS_PATH_SEPARATOR;
        if((ret < 0) && (errno != EEXIST)) {
            return ret;
        }
        x++;
    }
    return 0;
}

void dump_hex(const void* data, size_t byte_count) {
    byte_count = std::min(byte_count, size_t(16));

    const uint8_t* p = reinterpret_cast<const uint8_t*>(data);

    std::string line;
    for (size_t i = 0; i < byte_count; ++i) {
        android::base::StringAppendF(&line, "%02x", p[i]);
    }
    line.push_back(' ');

    for (size_t i = 0; i < byte_count; ++i) {
        int c = p[i];
        if (c < 32 || c > 127) {
            c = '.';
        }
        line.push_back(c);
    }

    DR("%s\n", line.c_str());
}

bool parse_host_and_port(const std::string& address,
                         std::string* canonical_address,
                         std::string* host, int* port,
                         std::string* error) {
    host->clear();

    bool ipv6 = true;
    bool saw_port = false;
    size_t colons = std::count(address.begin(), address.end(), ':');
    size_t dots = std::count(address.begin(), address.end(), '.');
    std::string port_str;
    if (address[0] == '[') {
      // [::1]:123
      if (address.rfind("]:") == std::string::npos) {
        *error = android::base::StringPrintf("bad IPv6 address '%s'", address.c_str());
        return false;
      }
      *host = address.substr(1, (address.find("]:") - 1));
      port_str = address.substr(address.rfind("]:") + 2);
      saw_port = true;
    } else if (dots == 0 && colons >= 2 && colons <= 7) {
      // ::1
      *host = address;
    } else if (colons <= 1) {
      // 1.2.3.4 or some.accidental.domain.com
      ipv6 = false;
      std::vector<std::string> pieces = android::base::Split(address, ":");
      *host = pieces[0];
      if (pieces.size() > 1) {
        port_str = pieces[1];
        saw_port = true;
      }
    }

    if (host->empty()) {
      *error = android::base::StringPrintf("no host in '%s'", address.c_str());
      return false;
    }

    if (saw_port) {
      if (sscanf(port_str.c_str(), "%d", port) != 1 || *port <= 0 || *port > 65535) {
        *error = android::base::StringPrintf("bad port number '%s' in '%s'",
                                             port_str.c_str(), address.c_str());
        return false;
      }
    }

    *canonical_address = android::base::StringPrintf(ipv6 ? "[%s]:%d" : "%s:%d", host->c_str(), *port);
    LOG(DEBUG) << "parsed " << address << " as " << *host << " and " << *port
               << " (" << *canonical_address << ")";
    return true;
}

int network_connect(const std::string& host, int port, int type, int timeout, std::string* error) {
    int getaddrinfo_error = 0;
    int fd = socket_network_client_timeout(host.c_str(), port, type, timeout, &getaddrinfo_error);
    if (fd != -1) {
        return fd;
    }
    if (getaddrinfo_error != 0) {
        // TODO: gai_strerror is not thread safe on Win32.
        *error = gai_strerror(getaddrinfo_error);
    } else {
        *error = strerror(errno);
    }
    return -1;
}
