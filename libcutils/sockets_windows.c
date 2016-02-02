/*
 * Copyright (C) 2015 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <cutils/sockets.h>

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms741549(v=vs.85).aspx
// claims WSACleanup() should be called before program exit, but general
// consensus seems to be that it hasn't actually been necessary for a long time,
// likely since Windows 3.1. Additionally, trying to properly use WSACleanup()
// can be extremely tricky and cause deadlock when using threads or atexit().
//
// Both adb (1) and Chrome (2) purposefully avoid WSACleanup() with no issues.
// (1) https://android.googlesource.com/platform/system/core.git/+/master/adb/sysdeps_win32.cpp
// (2) https://code.google.com/p/chromium/codesearch#chromium/src/net/base/winsock_init.cc
bool initialize_windows_sockets() {
    // There's no harm in calling WSAStartup() multiple times but no benefit
    // either, we may as well skip it after the first.
    static bool init_success = false;

    if (!init_success) {
        WSADATA wsaData;
        init_success = (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0);
    }

    return init_success;
}

int socket_close(cutils_socket_t sock) {
    return closesocket(sock);
}

int socket_set_receive_timeout(cutils_socket_t sock, int timeout_ms) {
    return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_ms,
                      sizeof(timeout_ms));
}

cutils_socket_buffer_t make_cutils_socket_buffer(void* data, size_t length) {
    cutils_socket_buffer_t buffer;
    buffer.buf = data;
    buffer.len = length;
    return buffer;
}

ssize_t socket_send_buffers(cutils_socket_t sock,
                            cutils_socket_buffer_t* buffers,
                            size_t num_buffers) {
    DWORD bytes_sent = 0;

    if (WSASend(sock, buffers, num_buffers, &bytes_sent, 0, NULL, NULL) !=
            SOCKET_ERROR) {
        return bytes_sent;
    }
    return -1;
}
