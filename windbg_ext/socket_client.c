#define WIN32_LEAN_AND_MEAN

#include "socket_client.h"

#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

static SOCKET g_socket = INVALID_SOCKET;
static int g_wsa_started = 0;
static char g_last_error[256] = "not connected";
static char g_recv_buffer[8192];
static unsigned long g_recv_buffer_len = 0;

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

    g_recv_buffer_len = 0;
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

static int DvsTryPopLine(char *line, unsigned long line_size)
{
    unsigned long i;
    unsigned long line_len;

    for (i = 0; i < g_recv_buffer_len; i++) {
        if (g_recv_buffer[i] == '\n') {
            line_len = i;
            if (line_len > 0 && g_recv_buffer[line_len - 1] == '\r') {
                line_len--;
            }
            if (line_len >= line_size) {
                snprintf(g_last_error, sizeof(g_last_error), "received JSONL line too long");
                g_last_error[sizeof(g_last_error) - 1] = '\0';
                g_recv_buffer_len = 0;
                return DVS_SOCKET_ERROR;
            }

            memcpy(line, g_recv_buffer, line_len);
            line[line_len] = '\0';

            i++;
            memmove(g_recv_buffer, g_recv_buffer + i, g_recv_buffer_len - i);
            g_recv_buffer_len -= i;
            return DVS_SOCKET_OK;
        }
    }

    return DVS_SOCKET_TIMEOUT;
}

int DvsSocketReceiveLine(char *line, unsigned long line_size, unsigned long timeout_ms)
{
    int pop_rc;
    fd_set read_set;
    struct timeval tv;
    int select_rc;
    int recv_rc;

    if (!DvsSocketIsConnected()) {
        snprintf(g_last_error, sizeof(g_last_error), "not connected");
        g_last_error[sizeof(g_last_error) - 1] = '\0';
        return DVS_SOCKET_ERROR;
    }

    if (line == NULL || line_size == 0) {
        snprintf(g_last_error, sizeof(g_last_error), "invalid receive line buffer");
        g_last_error[sizeof(g_last_error) - 1] = '\0';
        return DVS_SOCKET_ERROR;
    }

    pop_rc = DvsTryPopLine(line, line_size);
    if (pop_rc != DVS_SOCKET_TIMEOUT) {
        return pop_rc;
    }

    FD_ZERO(&read_set);
    FD_SET(g_socket, &read_set);
    tv.tv_sec = (long)(timeout_ms / 1000);
    tv.tv_usec = (long)((timeout_ms % 1000) * 1000);

    select_rc = select(0, &read_set, NULL, NULL, &tv);
    if (select_rc == 0) {
        return DVS_SOCKET_TIMEOUT;
    }
    if (select_rc == SOCKET_ERROR) {
        DvsSetLastErrorText("select", WSAGetLastError());
        DvsSocketDisconnect();
        return DVS_SOCKET_ERROR;
    }

    if (g_recv_buffer_len >= sizeof(g_recv_buffer)) {
        snprintf(g_last_error, sizeof(g_last_error), "receive buffer full without newline");
        g_last_error[sizeof(g_last_error) - 1] = '\0';
        g_recv_buffer_len = 0;
        return DVS_SOCKET_ERROR;
    }

    recv_rc = recv(
        g_socket,
        g_recv_buffer + g_recv_buffer_len,
        (int)(sizeof(g_recv_buffer) - g_recv_buffer_len),
        0);
    if (recv_rc == SOCKET_ERROR) {
        DvsSetLastErrorText("recv", WSAGetLastError());
        DvsSocketDisconnect();
        return DVS_SOCKET_ERROR;
    }
    if (recv_rc == 0) {
        snprintf(g_last_error, sizeof(g_last_error), "socket closed");
        g_last_error[sizeof(g_last_error) - 1] = '\0';
        DvsSocketDisconnect();
        return DVS_SOCKET_ERROR;
    }

    g_recv_buffer_len += (unsigned long)recv_rc;
    return DvsTryPopLine(line, line_size);
}
