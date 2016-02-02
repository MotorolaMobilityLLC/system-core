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

// This file provides a class interface for cross-platform socket functionality. The main fastboot
// engine should not be using this interface directly, but instead should use a higher-level
// interface that enforces the fastboot protocol.

#ifndef SOCKET_H_
#define SOCKET_H_

#include <memory>
#include <string>

#include <android-base/macros.h>
#include <cutils/sockets.h>

// Socket interface to be implemented for each platform.
class Socket {
  public:
    enum class Protocol { kTcp, kUdp };

    // Returns the socket error message. This must be called immediately after a socket failure
    // before any other system calls are made.
    static std::string GetErrorMessage();

    // Creates a new client connection. Clients are connected to a specific hostname/port and can
    // only send to that destination.
    // On failure, |error| is filled (if non-null) and nullptr is returned.
    static std::unique_ptr<Socket> NewClient(Protocol protocol, const std::string& hostname,
                                             int port, std::string* error);

    // Creates a new server bound to local |port|. This is only meant for testing, during normal
    // fastboot operation the device acts as the server.
    // A UDP server saves sender addresses in Receive(), and uses the most recent address during
    // calls to Send().
    static std::unique_ptr<Socket> NewServer(Protocol protocol, int port);

    // Destructor closes the socket if it's open.
    virtual ~Socket();

    // Sends |length| bytes of |data|. For TCP sockets this will continue trying to send until all
    // bytes are transmitted. Returns the number of bytes actually sent or -1 on error.
    virtual ssize_t Send(const void* data, size_t length) = 0;

    // Waits up to |timeout_ms| to receive up to |length| bytes of data. |timout_ms| of 0 will
    // block forever. Returns the number of bytes received or -1 on error/timeout. On timeout
    // errno will be set to EAGAIN or EWOULDBLOCK.
    virtual ssize_t Receive(void* data, size_t length, int timeout_ms) = 0;

    // Calls Receive() until exactly |length| bytes have been received or an error occurs.
    virtual ssize_t ReceiveAll(void* data, size_t length, int timeout_ms);

    // Closes the socket. Returns 0 on success, -1 on error.
    virtual int Close();

    // Accepts an incoming TCP connection. No effect for UDP sockets. Returns a new Socket
    // connected to the client on success, nullptr on failure.
    virtual std::unique_ptr<Socket> Accept() { return nullptr; }

    // Returns the local port the Socket is bound to or -1 on error.
    int GetLocalPort();

  protected:
    // Protected constructor to force factory function use.
    Socket(cutils_socket_t sock);

    // Update the socket receive timeout if necessary.
    bool SetReceiveTimeout(int timeout_ms);

    cutils_socket_t sock_ = INVALID_SOCKET;

  private:
    int receive_timeout_ms_ = 0;

    DISALLOW_COPY_AND_ASSIGN(Socket);
};

#endif  // SOCKET_H_
