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
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dbgeng_ops.h"
#include "json_writer.h"
#include "socket_client.h"

#define DVS_JSON_BUFFER_SIZE 1024
#define DVS_LINE_BUFFER_SIZE 4096
#define DVS_DEFAULT_PUMP_MESSAGES 16
#define DVS_POLL_TIMEOUT_MS 250

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

static unsigned long DvsParseOptionalUnsigned(const char *args, unsigned long default_value)
{
    unsigned long value = default_value;

    if (args == NULL) {
        return default_value;
    }
    while (*args != '\0' && isspace((unsigned char)*args)) {
        args++;
    }
    if (*args == '\0') {
        return default_value;
    }
    if (sscanf(args, "%lu", &value) != 1 || value == 0) {
        return default_value;
    }
    return value;
}

static int DvsExtractJsonStringField(const char *json, const char *field, char *out, unsigned long out_size)
{
    char pattern[64];
    const char *pos;
    const char *colon;
    const char *start;
    const char *end;
    unsigned long len;

    if (out_size == 0) {
        return 0;
    }
    out[0] = '\0';

    snprintf(pattern, sizeof(pattern), "\"%s\"", field);
    pattern[sizeof(pattern) - 1] = '\0';
    pos = strstr(json, pattern);
    if (pos == NULL) {
        return 0;
    }
    colon = strchr(pos + strlen(pattern), ':');
    if (colon == NULL) {
        return 0;
    }
    start = colon + 1;
    while (*start != '\0' && isspace((unsigned char)*start)) {
        start++;
    }
    if (*start != '"') {
        return 0;
    }
    start++;
    end = strchr(start, '"');
    if (end == NULL) {
        return 0;
    }
    len = (unsigned long)(end - start);
    if (len >= out_size) {
        return 0;
    }
    memcpy(out, start, len);
    out[len] = '\0';
    return 1;
}

static int DvsExtractJsonUnsignedField(const char *json, const char *field, unsigned long *out)
{
    char pattern[64];
    const char *pos;
    const char *colon;
    const char *start;

    snprintf(pattern, sizeof(pattern), "\"%s\"", field);
    pattern[sizeof(pattern) - 1] = '\0';
    pos = strstr(json, pattern);
    if (pos == NULL) {
        return 0;
    }
    colon = strchr(pos + strlen(pattern), ':');
    if (colon == NULL) {
        return 0;
    }
    start = colon + 1;
    while (*start != '\0' && isspace((unsigned char)*start)) {
        start++;
    }
    return sscanf(start, "%lu", out) == 1;
}

static void DvsLowerAscii(char *text)
{
    while (*text != '\0') {
        *text = (char)tolower((unsigned char)*text);
        text++;
    }
}

static int DvsParseRegisterList(
    const char *json,
    char names[][DVS_REGISTER_NAME_MAX],
    unsigned long max_names,
    unsigned long *name_count)
{
    const char *pos;
    const char *array;
    unsigned long count = 0;

    *name_count = 0;
    pos = strstr(json, "\"registers\"");
    if (pos == NULL) {
        return 0;
    }
    array = strchr(pos, '[');
    if (array == NULL) {
        return 0;
    }
    array++;

    while (*array != '\0' && *array != ']') {
        const char *start;
        const char *end;
        unsigned long len;

        while (*array != '\0' && *array != ']' && *array != '"') {
            array++;
        }
        if (*array == ']') {
            break;
        }
        if (*array != '"') {
            return 0;
        }
        start = array + 1;
        end = strchr(start, '"');
        if (end == NULL) {
            return 0;
        }
        len = (unsigned long)(end - start);
        if (len == 0 || len >= DVS_REGISTER_NAME_MAX || count >= max_names) {
            return 0;
        }
        memcpy(names[count], start, len);
        names[count][len] = '\0';
        DvsLowerAscii(names[count]);
        count++;
        array = end + 1;
    }

    *name_count = count;
    return count > 0;
}

static int DvsHandleRegRequest(PDEBUG_CLIENT client, const char *line)
{
    unsigned long pc_seq = 0;
    char request_id[128];
    char runtime_pc[64];
    char names[DVS_MAX_REGISTER_VALUES][DVS_REGISTER_NAME_MAX];
    unsigned long name_count = 0;
    DVS_REGISTER_VALUE values[DVS_MAX_REGISTER_VALUES];
    unsigned long value_count = 0;
    char json[DVS_JSON_BUFFER_SIZE * 4];

    if (!DvsExtractJsonUnsignedField(line, "pc_seq", &pc_seq) ||
        !DvsExtractJsonStringField(line, "request_id", request_id, sizeof(request_id)) ||
        !DvsExtractJsonStringField(line, "runtime_pc", runtime_pc, sizeof(runtime_pc)) ||
        !DvsParseRegisterList(line, names, DVS_MAX_REGISTER_VALUES, &name_count)) {
        DvsOutput(client, "dayvar: invalid reg_request ignored\n");
        return 0;
    }

    if (DvsReadRegisters(client, names, name_count, values, &value_count) != DVS_DBGENG_OK) {
        DvsOutput(client, "dayvar: register read failed: %s\n", DvsDbgEngLastError());
        return 0;
    }

    if (DvsWriteRegResponse(
            json,
            sizeof(json),
            DvsNextMessageId(),
            pc_seq,
            request_id,
            runtime_pc,
            values,
            value_count) != DVS_JSON_OK) {
        DvsOutput(client, "dayvar: failed to build reg_response JSON\n");
        return 0;
    }

    if (!DvsSendJson(client, json)) {
        return 0;
    }

    DvsOutput(client, "dayvar: sent reg_response pc_seq=%lu request_id=%s registers=%lu\n", pc_seq, request_id, value_count);
    return 1;
}

static void DvsHandleIncomingMessage(PDEBUG_CLIENT client, const char *line)
{
    char type[64];

    if (!DvsExtractJsonStringField(line, "type", type, sizeof(type))) {
        DvsOutput(client, "dayvar: ignored malformed incoming message\n");
        return;
    }

    if (strcmp(type, "reg_request") == 0) {
        DvsHandleRegRequest(client, line);
    } else if (strcmp(type, "mem_request") == 0) {
        DvsOutput(client, "dayvar: mem_request ignored; not implemented yet\n");
    } else {
        DvsOutput(client, "dayvar: ignored incoming message type=%s\n", type);
    }
}

static unsigned long DvsPumpBroker(PDEBUG_CLIENT client, unsigned long max_messages)
{
    unsigned long handled = 0;

    while (handled < max_messages) {
        char line[DVS_LINE_BUFFER_SIZE];
        int rc = DvsSocketReceiveLine(line, sizeof(line), DVS_POLL_TIMEOUT_MS);

        if (rc == DVS_SOCKET_TIMEOUT) {
            break;
        }
        if (rc != DVS_SOCKET_OK) {
            DvsOutput(client, "dayvar: broker receive failed: %s\n", DvsSocketLastError());
            break;
        }

        DvsHandleIncomingMessage(client, line);
        handled++;
    }

    return handled;
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

    DvsPumpBroker(Client, DVS_DEFAULT_PUMP_MESSAGES);

    return S_OK;
}

__declspec(dllexport) HRESULT CALLBACK dvs_poll(PDEBUG_CLIENT Client, PCSTR args)
{
    unsigned long max_messages;
    unsigned long handled;

    if (!DvsSocketIsConnected()) {
        DvsOutput(Client, "dayvar: not connected; run !dvs_connect <host> <port>\n");
        return E_FAIL;
    }

    max_messages = DvsParseOptionalUnsigned(args, DVS_DEFAULT_PUMP_MESSAGES);
    handled = DvsPumpBroker(Client, max_messages);
    DvsOutput(Client, "dayvar: poll handled %lu message(s)\n", handled);
    return S_OK;
}
