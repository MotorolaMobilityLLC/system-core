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

// Tests socket functionality using loopback connections. Requires IPv4 and
// IPv6 capabilities. These tests assume that no UDP packets are lost, which
// should be the case for loopback communication, but is not guaranteed.

#include <cutils/sockets.h>

#include <time.h>

#include <gtest/gtest.h>

// Makes sure the passed sockets are valid, sends data between them, and closes
// them. Any failures are logged with gtest.
//
// On Mac recvfrom() will not fill in the address for TCP sockets, so we need
// separate logic paths depending on socket type.
static void TestConnectedSockets(cutils_socket_t server, cutils_socket_t client,
                                 int type) {
    ASSERT_NE(INVALID_SOCKET, server);
    ASSERT_NE(INVALID_SOCKET, client);

    char buffer[128];
    sockaddr_storage addr;
    socklen_t addr_size = sizeof(addr);

    // Send client -> server first to get the UDP client's address.
    ASSERT_EQ(3, send(client, "foo", 3, 0));
    if (type == SOCK_DGRAM) {
        EXPECT_EQ(3, recvfrom(server, buffer, sizeof(buffer), 0,
                              reinterpret_cast<sockaddr*>(&addr), &addr_size));
    } else {
        EXPECT_EQ(3, recv(server, buffer, sizeof(buffer), 0));
    }
    EXPECT_EQ(0, memcmp(buffer, "foo", 3));

    // Now send server -> client.
    if (type == SOCK_DGRAM) {
        ASSERT_EQ(3, sendto(server, "bar", 3, 0,
                            reinterpret_cast<sockaddr*>(&addr), addr_size));
    } else {
        ASSERT_EQ(3, send(server, "bar", 3, 0));
    }
    EXPECT_EQ(3, recv(client, buffer, sizeof(buffer), 0));
    EXPECT_EQ(0, memcmp(buffer, "bar", 3));

    // Send multiple buffers using socket_send_buffers().
    std::string data[] = {"foo", "bar", "12345"};
    cutils_socket_buffer_t socket_buffers[3];
    for (int i = 0; i < 3; ++i) {
        socket_buffers[i] = make_cutils_socket_buffer(&data[i][0],
                                                      data[i].length());
    }
    EXPECT_EQ(11, socket_send_buffers(client, socket_buffers, 3));
    EXPECT_EQ(11, recv(server, buffer, sizeof(buffer), 0));
    EXPECT_EQ(0, memcmp(buffer, "foobar12345", 11));

    EXPECT_EQ(0, socket_close(server));
    EXPECT_EQ(0, socket_close(client));
}

// Tests receive timeout. The timing verification logic must be very coarse to
// make sure different systems can all pass these tests.
void TestReceiveTimeout(cutils_socket_t sock) {
    time_t start_time;
    char buffer[32];

    // Make sure a 20ms timeout completes in 1 second or less.
    EXPECT_EQ(0, socket_set_receive_timeout(sock, 20));
    start_time = time(nullptr);
    EXPECT_EQ(-1, recv(sock, buffer, sizeof(buffer), 0));
    EXPECT_LE(difftime(time(nullptr), start_time), 1.0);

    // Make sure a 1250ms timeout takes 1 second or more.
    EXPECT_EQ(0, socket_set_receive_timeout(sock, 1250));
    start_time = time(nullptr);
    EXPECT_EQ(-1, recv(sock, buffer, sizeof(buffer), 0));
    EXPECT_LE(1.0, difftime(time(nullptr), start_time));
}

// Tests socket_get_local_port().
TEST(SocketsTest, TestGetLocalPort) {
    cutils_socket_t server;

    // Check a bunch of ports so that we can ignore any conflicts in case
    // of ports already being taken, but if a server is able to start up we
    // should always be able to read its port.
    for (int port : {10000, 12345, 15999, 20202, 25000}) {
        for (int type : {SOCK_DGRAM, SOCK_STREAM}) {
            server = socket_inaddr_any_server(port, SOCK_DGRAM);
            if (server != INVALID_SOCKET) {
                EXPECT_EQ(port, socket_get_local_port(server));
            }
            socket_close(server);
        }
    }

    // Check expected failure for an invalid socket.
    EXPECT_EQ(-1, socket_get_local_port(INVALID_SOCKET));
}

// Tests socket_inaddr_any_server() and socket_network_client() for IPv4 UDP.
TEST(SocketsTest, TestIpv4UdpLoopback) {
    cutils_socket_t server = socket_inaddr_any_server(0, SOCK_DGRAM);
    cutils_socket_t client = socket_network_client(
            "127.0.0.1", socket_get_local_port(server), SOCK_DGRAM);

    TestConnectedSockets(server, client, SOCK_DGRAM);
}

// Tests socket_inaddr_any_server() and socket_network_client() for IPv4 TCP.
TEST(SocketsTest, TestIpv4TcpLoopback) {
    cutils_socket_t server = socket_inaddr_any_server(0, SOCK_STREAM);
    ASSERT_NE(INVALID_SOCKET, server);

    cutils_socket_t client = socket_network_client(
            "127.0.0.1", socket_get_local_port(server), SOCK_STREAM);
    cutils_socket_t handler = accept(server, nullptr, nullptr);
    EXPECT_EQ(0, socket_close(server));

    TestConnectedSockets(handler, client, SOCK_STREAM);
}

// Tests socket_inaddr_any_server() and socket_network_client() for IPv6 UDP.
TEST(SocketsTest, TestIpv6UdpLoopback) {
    cutils_socket_t server = socket_inaddr_any_server(0, SOCK_DGRAM);
    cutils_socket_t client = socket_network_client(
            "::1", socket_get_local_port(server), SOCK_DGRAM);

    TestConnectedSockets(server, client, SOCK_DGRAM);
}

// Tests socket_inaddr_any_server() and socket_network_client() for IPv6 TCP.
TEST(SocketsTest, TestIpv6TcpLoopback) {
    cutils_socket_t server = socket_inaddr_any_server(0, SOCK_STREAM);
    ASSERT_NE(INVALID_SOCKET, server);

    cutils_socket_t client = socket_network_client(
            "::1", socket_get_local_port(server), SOCK_STREAM);
    cutils_socket_t handler = accept(server, nullptr, nullptr);
    EXPECT_EQ(0, socket_close(server));

    TestConnectedSockets(handler, client, SOCK_STREAM);
}

// Tests setting a receive timeout for UDP sockets.
TEST(SocketsTest, TestUdpReceiveTimeout) {
    cutils_socket_t sock = socket_inaddr_any_server(0, SOCK_DGRAM);
    ASSERT_NE(INVALID_SOCKET, sock);

    TestReceiveTimeout(sock);

    EXPECT_EQ(0, socket_close(sock));
}

// Tests setting a receive timeout for TCP sockets.
TEST(SocketsTest, TestTcpReceiveTimeout) {
    cutils_socket_t server = socket_inaddr_any_server(0, SOCK_STREAM);
    ASSERT_NE(INVALID_SOCKET, server);

    cutils_socket_t client = socket_network_client(
            "localhost", socket_get_local_port(server), SOCK_STREAM);
    cutils_socket_t handler = accept(server, nullptr, nullptr);
    EXPECT_EQ(0, socket_close(server));

    TestReceiveTimeout(handler);

    EXPECT_EQ(0, socket_close(client));
    EXPECT_EQ(0, socket_close(handler));
}

// Tests socket_send_buffers() failure.
TEST(SocketsTest, TestSocketSendBuffersFailure) {
    EXPECT_EQ(-1, socket_send_buffers(INVALID_SOCKET, nullptr, 0));
}
