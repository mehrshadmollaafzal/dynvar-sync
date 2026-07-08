#define WIN32_LEAN_AND_MEAN

#include "socket_client.h"

#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

static SOCKET g_socket = INVALID_SOCKET;
static int g_wsa_started = 0;
static char g_last_error[256] = "not connected";

static void DvsSetLastErrorText(const char *prefix, int error_code)
{
    snprintf(
        g_last_error,
        sizeof(g_last_error),
        "%s failed with error %d",
        prefix,
        error_code);
    g_last_error[sizeof(g_last_error) - 1] = '\0';
}

const char *DvsSocketLastError(void)
{
    return g_last_error;
}

int DvsSocketIsConnected(void)
{
    return g_socket != INVALID_SOCKET;
}

int DvsSocketConnect(const char *host, unsigned short port)
{
    WSADATA wsa_data;
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *it = NULL;
    char port_text[16];
    int rc;

    if (DvsSocketIsConnected()) {
        DvsSocketDisconnect();
    }

    rc = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (rc != 0) {
        DvsSetLastErrorText("WSAStartup", rc);
        return DVS_SOCKET_ERROR;
    }
    g_wsa_started = 1;

    snprintf(port_text, sizeof(port_text), "%u", (unsigned int)port);
    port_text[sizeof(port_text) - 1] = '\0';

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    rc = getaddrinfo(host, port_text, &hints, &result);
    if (rc != 0) {
        DvsSetLastErrorText("getaddrinfo", rc);
        DvsSocketDisconnect();
        return DVS_SOCKET_ERROR;
    }

    for (it = result; it != NULL; it = it->ai_next) {
        SOCKET candidate = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (candidate == INVALID_SOCKET) {
            continue;
        }

        if (connect(candidate, it->ai_addr, (int)it->ai_addrlen) == 0) {
            g_socket = candidate;
            break;
        }

        closesocket(candidate);
    }

    freeaddrinfo(result);

    if (g_socket == INVALID_SOCKET) {
        DvsSetLastErrorText("connect", WSAGetLastError());
        DvsSocketDisconnect();
        return DVS_SOCKET_ERROR;
    }

    snprintf(g_last_error, sizeof(g_last_error), "ok");
    g_last_error[sizeof(g_last_error) - 1] = '\0';
    return DVS_SOCKET_OK;
}

void DvsSocketDisconnect(void)
{
    if (g_socket != INVALID_SOCKET) {
        closesocket(g_socket);
        g_socket = INVALID_SOCKET;
    }

    if (g_wsa_started) {
        WSACleanup();
        g_wsa_started = 0;
    }
}

int DvsSocketSendAll(const char *data, unsigned long data_len)
{
    unsigned long sent_total = 0;

    if (!DvsSocketIsConnected()) {
        snprintf(g_last_error, sizeof(g_last_error), "not connected");
        g_last_error[sizeof(g_last_error) - 1] = '\0';
        return DVS_SOCKET_ERROR;
    }

    while (sent_total < data_len) {
        int sent = send(
            g_socket,
            data + sent_total,
            (int)(data_len - sent_total),
            0);
        if (sent == SOCKET_ERROR) {
            DvsSetLastErrorText("send", WSAGetLastError());
            DvsSocketDisconnect();
            return DVS_SOCKET_ERROR;
        }
        if (sent == 0) {
            snprintf(g_last_error, sizeof(g_last_error), "socket closed");
            g_last_error[sizeof(g_last_error) - 1] = '\0';
            DvsSocketDisconnect();
            return DVS_SOCKET_ERROR;
        }
        sent_total += (unsigned long)sent;
    }

    return DVS_SOCKET_OK;
}
