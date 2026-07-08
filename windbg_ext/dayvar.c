/*
 * DayVar Sync WinDbg extension, Phase 2.
 *
 * This phase implements connect/disconnect/status/pc_update only. DbgEng
 * PC/module extraction is isolated in dbgeng_ops.c.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <initguid.h>
#include <dbgeng.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dbgeng_ops.h"
#include "json_writer.h"
#include "socket_client.h"

#define DVS_JSON_BUFFER_SIZE 1024

static unsigned long g_next_message_id = 1;
static unsigned long g_next_pc_seq = 1;
static char g_connected_host[256] = "";
static unsigned short g_connected_port = 0;

static void DvsCopyString(char *dst, unsigned long dst_size, const char *src)
{
    if (dst_size == 0) {
        return;
    }
    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

static void DvsOutput(PDEBUG_CLIENT client, const char *format, ...)
{
    char buffer[1024];
    va_list args;
    HRESULT hr;
    PDEBUG_CONTROL3 control = NULL;

    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    buffer[sizeof(buffer) - 1] = '\0';
    va_end(args);

    if (client == NULL) {
        OutputDebugStringA(buffer);
        return;
    }

    hr = client->lpVtbl->QueryInterface(
        client,
        &IID_IDebugControl3,
        (void **)&control);
    if (FAILED(hr) || control == NULL) {
        OutputDebugStringA(buffer);
        return;
    }

    control->lpVtbl->Output(control, DEBUG_OUTPUT_NORMAL, "%s", buffer);
    control->lpVtbl->Release(control);
}

static unsigned long DvsNextMessageId(void)
{
    return g_next_message_id++;
}

static unsigned long DvsNextPcSeq(void)
{
    return g_next_pc_seq++;
}

static int DvsSendJson(PDEBUG_CLIENT client, const char *json)
{
    unsigned long len = (unsigned long)strlen(json);

    if (DvsSocketSendAll(json, len) != DVS_SOCKET_OK) {
        DvsOutput(client, "dayvar: send failed: %s\n", DvsSocketLastError());
        return 0;
    }
    return 1;
}

static int DvsParseConnectArgs(const char *args, char *host, unsigned long host_size, unsigned int *port)
{
    char parsed_host[256];
    unsigned int parsed_port;

    if (args == NULL) {
        return 0;
    }

    parsed_host[0] = '\0';
    parsed_port = 0;

    if (sscanf(args, "%255s %u", parsed_host, &parsed_port) != 2) {
        return 0;
    }

    if (parsed_port == 0 || parsed_port > 65535) {
        return 0;
    }

    DvsCopyString(host, host_size, parsed_host);
    *port = parsed_port;
    return 1;
}

HRESULT CALLBACK DebugExtensionInitialize(PULONG Version, PULONG Flags)
{
    if (Version != NULL) {
        *Version = DEBUG_EXTENSION_VERSION(1, 0);
    }
    if (Flags != NULL) {
        *Flags = 0;
    }
    return S_OK;
}

void CALLBACK DebugExtensionUninitialize(void)
{
    DvsSocketDisconnect();
}

HRESULT CALLBACK dvs_connect(PDEBUG_CLIENT Client, PCSTR args)
{
    char host[256];
    unsigned int port;
    char json[DVS_JSON_BUFFER_SIZE];

    if (!DvsParseConnectArgs(args, host, sizeof(host), &port)) {
        DvsOutput(Client, "usage: !dvs_connect <host> <port>\n");
        return E_INVALIDARG;
    }

    if (DvsSocketConnect(host, (unsigned short)port) != DVS_SOCKET_OK) {
        DvsOutput(Client, "dayvar: connect failed: %s\n", DvsSocketLastError());
        return E_FAIL;
    }

    DvsCopyString(g_connected_host, sizeof(g_connected_host), host);
    g_connected_port = (unsigned short)port;

    if (DvsWriteHello(json, sizeof(json), DvsNextMessageId()) != DVS_JSON_OK) {
        DvsOutput(Client, "dayvar: failed to build hello JSON\n");
        DvsSocketDisconnect();
        return E_FAIL;
    }

    if (!DvsSendJson(Client, json)) {
        return E_FAIL;
    }

    DvsOutput(Client, "dayvar: connected to %s:%u and sent hello\n", host, port);
    return S_OK;
}

HRESULT CALLBACK dvs_disconnect(PDEBUG_CLIENT Client, PCSTR args)
{
    (void)args;

    if (!DvsSocketIsConnected()) {
        DvsOutput(Client, "dayvar: not connected\n");
        return S_OK;
    }

    DvsSocketDisconnect();
    g_connected_host[0] = '\0';
    g_connected_port = 0;
    DvsOutput(Client, "dayvar: disconnected\n");
    return S_OK;
}

HRESULT CALLBACK dvs_status(PDEBUG_CLIENT Client, PCSTR args)
{
    (void)args;

    if (DvsSocketIsConnected()) {
        DvsOutput(
            Client,
            "dayvar: connected to %s:%u next_pc_seq=%lu\n",
            g_connected_host,
            (unsigned int)g_connected_port,
            g_next_pc_seq);
    } else {
        DvsOutput(Client, "dayvar: disconnected\n");
    }

    return S_OK;
}

HRESULT CALLBACK dvs_pc(PDEBUG_CLIENT Client, PCSTR args)
{
    DVS_PC_INFO pc_info;
    char json[DVS_JSON_BUFFER_SIZE];
    unsigned long message_id;
    unsigned long pc_seq;

    (void)args;

    if (!DvsSocketIsConnected()) {
        DvsOutput(Client, "dayvar: not connected; run !dvs_connect <host> <port>\n");
        return E_FAIL;
    }

    if (DvsReadCurrentPcInfo(Client, &pc_info) != DVS_DBGENG_OK) {
        DvsOutput(Client, "dayvar: failed to read PC/module info: %s\n", DvsDbgEngLastError());
        return E_FAIL;
    }

    message_id = DvsNextMessageId();
    pc_seq = DvsNextPcSeq();

    if (DvsWritePcUpdate(
            json,
            sizeof(json),
            message_id,
            pc_seq,
            pc_info.pc,
            pc_info.module,
            pc_info.runtime_module_base,
            "dvs_pc",
            1) != DVS_JSON_OK) {
        DvsOutput(Client, "dayvar: failed to build pc_update JSON\n");
        return E_FAIL;
    }

    if (!DvsSendJson(Client, json)) {
        return E_FAIL;
    }

    DvsOutput(
        Client,
        "dayvar: sent pc_update pc_seq=%lu pc=0x%016llx module=%s base=0x%016llx\n",
        pc_seq,
        pc_info.pc,
        pc_info.module,
        pc_info.runtime_module_base);

    return S_OK;
}
